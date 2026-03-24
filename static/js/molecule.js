import * as THREE from '/static/js/three.module.js';
import { CSS2DRenderer, CSS2DObject } from '/static/js/CSS2DRenderer.js';
import { OrbitControls } from '/static/js/OrbitControls.js';

// Apply dynamic styles from data attributes (CSP-safe, no inline styles)
document.querySelectorAll('[data-gradient]').forEach(el => { el.style.background = el.getAttribute('data-gradient'); });
document.querySelectorAll('[data-width]').forEach(el => { el.style.width = el.getAttribute('data-width'); });

// Molecule data injected by Go template into a JSON script tag
const moleculeData = JSON.parse(document.getElementById('molecule-data').textContent);

// Layout preference: "tetrahedral" (default), "helix", or "organic"
const layoutEl = document.getElementById('molecule-layout');
const layout = layoutEl ? JSON.parse(layoutEl.textContent) : 'tetrahedral';

const canvas = document.getElementById('molecule-canvas');
if (!canvas) throw new Error('Canvas not found');

const scene = new THREE.Scene();
const camera = new THREE.PerspectiveCamera(50, canvas.clientWidth / canvas.clientHeight, 0.1, 1000);
camera.position.set(0, 5, 16);

const renderer = new THREE.WebGLRenderer({ canvas, antialias: true, alpha: true });
renderer.setSize(canvas.clientWidth, canvas.clientHeight);
renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));

// CSS2D renderer for labels
const labelRenderer = new CSS2DRenderer();
labelRenderer.setSize(canvas.clientWidth, canvas.clientHeight);
labelRenderer.domElement.style.position = 'absolute';
labelRenderer.domElement.style.top = '0';
labelRenderer.domElement.style.left = '0';
labelRenderer.domElement.style.pointerEvents = 'none';
const moleculeContainer = canvas.closest('.molecule-container');
moleculeContainer.appendChild(labelRenderer.domElement);

// Orbit controls for mouse interaction
const controls = new OrbitControls(camera, canvas);
controls.enableDamping = true;
controls.dampingFactor = 0.05;
controls.enablePan = true;
controls.enableZoom = true;
controls.autoRotate = true;
controls.autoRotateSpeed = 1.0;

// Lighting
scene.add(new THREE.AmbientLight(0xffffff, 0.5));
const directionalLight = new THREE.DirectionalLight(0xffffff, 1);
directionalLight.position.set(5, 8, 5);
scene.add(directionalLight);
const backLight = new THREE.DirectionalLight(0xffffff, 0.4);
backLight.position.set(-5, -3, -5);
scene.add(backLight);
const rimLight = new THREE.DirectionalLight(0xffffff, 0.3);
rimLight.position.set(0, 0, -8);
scene.add(rimLight);

const moleculeGroup = new THREE.Group();
scene.add(moleculeGroup);

// Color mapping for severity
const severityColors = {
    hostile: 0xff6b6b,
    suspicious: 0xffd43b,
    notable: 0x74b9ff,
    neutral: 0xb8bec5
};

// Returns true if this atom is a dim supporting/neutral atom.
function isBaseline(atom) {
    return atom.severity === 'neutral' && !atom.ring && atom.category !== 'file';
}

// Track clickable meshes for raycasting
const clickableMeshes = [];
const meshToMolecule = new Map();
const meshToAtom = new Map();

// Deduplicate bonds and remove self-loops from a bond array.
function cleanBonds(bonds) {
    if (!bonds) return [];
    const seen = new Set();
    const result = [];
    for (const b of bonds) {
        const a = Math.min(b[0], b[1]), c = Math.max(b[0], b[1]);
        if (a === c) continue;
        const key = a + ',' + c;
        if (!seen.has(key)) { seen.add(key); result.push([a, c]); }
    }
    return result;
}

// Build adjacency list from atoms and clean bonds.
function buildAdj(atoms, bonds) {
    const adj = atoms.map(() => []);
    bonds.forEach(([a, b]) => { adj[a].push(b); adj[b].push(a); });
    return adj;
}

// ============================================================
// Layout algorithms — reposition atoms in-place before rendering
// ============================================================

function applyLayout(atoms, bonds, layoutName) {
    if (!atoms || atoms.length === 0) return;

    // Identify cluster satellite atoms — they follow their parent, not the layout.
    const clusterAtoms = new Set();
    atoms.forEach((a, i) => { if (a.cluster_of) clusterAtoms.add(i); });

    // Build adjacency excluding cluster satellites so layouts don't position them.
    const adj = atoms.map(() => []);
    bonds.forEach(([a, b]) => {
        if (clusterAtoms.has(a) || clusterAtoms.has(b)) return;
        adj[a].push(b); adj[b].push(a);
    });

    const ringArr = [];
    atoms.forEach((a, i) => { if (a.ring) ringArr.push(i); });
    if (ringArr.length === 0) return;
    const ringIds = new Set(ringArr);

    const layouts = {
        helix: layoutHelix,
        helix4: layoutHelix4,
        helix5: layoutHelix5,
        organic2: layoutOrganic2,
        organic4: layoutOrganic4,
        organic5: layoutOrganic5,
        flat: layoutFlat,
    };
    (layouts[layoutName] || layouts.helix)(atoms, adj, ringArr, ringIds);

    // Center non-cluster atoms first.
    let cx = 0, cy = 0, cz = 0, count = 0;
    atoms.forEach((a, i) => { if (!clusterAtoms.has(i)) { cx += a.x; cy += a.y; cz += a.z; count++; } });
    if (count > 0) { cx /= count; cy /= count; cz /= count; }
    atoms.forEach((a, i) => { if (!clusterAtoms.has(i)) { a.x -= cx; a.y -= cy; a.z -= cz; } });

    // Reposition cluster satellites relative to their parent using stored offsets.
    atoms.forEach(a => {
        if (!a.cluster_of) return;
        const parentIdx = a.cluster_of - 1; // cluster_of is 1-indexed (0 = not clustered)
        const parent = atoms[parentIdx];
        if (!parent) return;
        a.x = parent.x + (a.cdx || 0);
        a.y = parent.y + (a.cdy || 0);
        a.z = parent.z + (a.cdz || 0);
    });
}

// ============================================================
// Shared: BFS deeper branches with wide arcs + force polish
// ============================================================
function bfsBranch3D(atoms, adj, placed, queue, opts) {
    const { bondLen = 2.0, decay = 0.08, minLen = 0.7 } = opts || {};
    while (queue.length > 0) {
        const { id, angle, depth, prevZ } = queue.shift();
        const children = adj[id].filter(n => !placed.has(n));
        if (!children.length) continue;
        const len = bondLen * Math.max(minLen, 1 - depth * decay);
        children.forEach((cid, ci) => {
            const n = children.length;
            let a2;
            if (n === 1) a2 = angle + (depth % 2 ? 0.4 : -0.4);
            else { const s = Math.min(Math.PI * 0.85, Math.PI * 0.25 * n); a2 = angle - s / 2 + s * ci / (n - 1); }
            const zSign = ((ci + depth) % 2 === 0) ? 1 : -1;
            const tilt = Math.PI / 6;
            atoms[cid].x = atoms[id].x + len * Math.cos(a2) * Math.cos(tilt);
            atoms[cid].y = atoms[id].y + len * Math.sin(a2) * Math.cos(tilt) * (prevZ !== undefined ? 1 : 1);
            atoms[cid].z = atoms[id].z + len * Math.sin(tilt) * zSign * 0.6;
            placed.add(cid);
            queue.push({ id: cid, angle: a2, depth: depth + 1 });
        });
    }
}

function forcePolish(atoms, ringIds, iters = 60, threshold = 2.0) {
    const N = atoms.length;
    const vel = atoms.map(() => ({ x: 0, y: 0, z: 0 }));
    for (let iter = 0; iter < iters; iter++) {
        for (let i = 0; i < N; i++) {
            if (ringIds.has(i)) continue;
            for (let j = i + 1; j < N; j++) {
                if (ringIds.has(j)) continue;
                const dx = atoms[i].x - atoms[j].x, dy = atoms[i].y - atoms[j].y, dz = atoms[i].z - atoms[j].z;
                const d = Math.sqrt(dx*dx + dy*dy + dz*dz) || 0.01;
                if (d < threshold) {
                    const f = 0.15 * (threshold - d);
                    vel[i].x += dx/d*f; vel[i].y += dy/d*f; vel[i].z += dz/d*f;
                    vel[j].x -= dx/d*f; vel[j].y -= dy/d*f; vel[j].z -= dz/d*f;
                }
            }
        }
        for (let i = 0; i < N; i++) {
            if (ringIds.has(i)) continue;
            atoms[i].x += vel[i].x; atoms[i].y += vel[i].y; atoms[i].z += vel[i].z;
            vel[i].x *= 0.8; vel[i].y *= 0.8; vel[i].z *= 0.8;
        }
    }
}

// ============================================================
// Layout: Helix (original favorite)
// ============================================================
function layoutHelix(atoms, adj, ringArr, ringIds) {
    const HR = 1.8, HP = 3.0, TURNS = 0.28, BR = 2.2;
    ringArr.forEach((id, i) => {
        const t = i * TURNS * 2 * Math.PI;
        atoms[id].x = HR * Math.cos(t);
        atoms[id].z = HR * Math.sin(t);
        atoms[id].y = i * HP * TURNS;
    });
    const midY = (ringArr.length - 1) * HP * TURNS / 2;
    ringArr.forEach(id => { atoms[id].y -= midY; });

    const placed = new Set(ringArr);
    const queue = [];
    ringArr.forEach(id => {
        const a = atoms[id];
        const helixAngle = Math.atan2(a.z, a.x);
        const children = adj[id].filter(n => !placed.has(n));
        children.forEach((cid, ci) => {
            const n = children.length;
            const spread = Math.PI * 0.7;
            const angle = n === 1 ? helixAngle : helixAngle - spread / 2 + spread * ci / (n - 1);
            const tilt = Math.PI / 5;
            const zSign = (ci % 2 === 0) ? 1 : -1;
            atoms[cid].x = a.x + BR * Math.cos(angle) * Math.cos(tilt);
            atoms[cid].z = a.z + BR * Math.sin(angle) * Math.cos(tilt);
            atoms[cid].y = a.y + BR * Math.sin(tilt) * zSign * 0.4;
            placed.add(cid);
            queue.push({ id: cid, angle, depth: 1 });
        });
    });
    bfsBranch3D(atoms, adj, placed, queue);
}

// ============================================================
// Layout: Helix4 — wider pitch, more vertical separation, force polish
// ============================================================
function layoutHelix4(atoms, adj, ringArr, ringIds) {
    const HR = 2.0, HP = 4.0, TURNS = 0.35, BR = 2.5;
    ringArr.forEach((id, i) => {
        const t = i * TURNS * 2 * Math.PI;
        atoms[id].x = HR * Math.cos(t);
        atoms[id].z = HR * Math.sin(t);
        atoms[id].y = i * HP * TURNS;
    });
    const midY = (ringArr.length - 1) * HP * TURNS / 2;
    ringArr.forEach(id => { atoms[id].y -= midY; });

    const placed = new Set(ringArr);
    const queue = [];
    ringArr.forEach(id => {
        const a = atoms[id];
        const helixAngle = Math.atan2(a.z, a.x);
        const children = adj[id].filter(n => !placed.has(n));
        children.forEach((cid, ci) => {
            const n = children.length;
            const spread = Math.PI * 0.8;
            const angle = n === 1 ? helixAngle : helixAngle - spread / 2 + spread * ci / (n - 1);
            // Branches extend perpendicular to helix axis (horizontal)
            atoms[cid].x = a.x + BR * Math.cos(angle);
            atoms[cid].z = a.z + BR * Math.sin(angle);
            atoms[cid].y = a.y + (ci % 2 === 0 ? 0.3 : -0.3);
            placed.add(cid);
            queue.push({ id: cid, angle, depth: 1 });
        });
    });
    bfsBranch3D(atoms, adj, placed, queue, { bondLen: 2.2 });
    forcePolish(atoms, ringIds, 40, 1.8);
}

// ============================================================
// Layout: Helix5 — tight helix, steep outward branches, dramatic 3D
// ============================================================
function layoutHelix5(atoms, adj, ringArr, ringIds) {
    const HR = 1.5, HEIGHT_PER = 3.5, FULL_TURNS = 1.0, BR = 2.0;
    const totalAngle = FULL_TURNS * 2 * Math.PI;
    ringArr.forEach((id, i) => {
        const t = totalAngle * i / (ringArr.length - 1 || 1);
        atoms[id].x = HR * Math.cos(t);
        atoms[id].z = HR * Math.sin(t);
        atoms[id].y = i * HEIGHT_PER;
    });
    const midY = (ringArr.length - 1) * HEIGHT_PER / 2;
    ringArr.forEach(id => { atoms[id].y -= midY; });

    const placed = new Set(ringArr);
    const queue = [];
    ringArr.forEach(id => {
        const a = atoms[id];
        const radial = Math.atan2(a.z, a.x);
        const children = adj[id].filter(n => !placed.has(n));
        children.forEach((cid, ci) => {
            const n = children.length;
            const spread = Math.PI * 0.75;
            const angle = n === 1 ? radial : radial - spread / 2 + spread * ci / (n - 1);
            const tilt = Math.PI / 4; // 45° steep
            const zSign = (ci % 2 === 0) ? 1 : -1;
            atoms[cid].x = a.x + BR * Math.cos(angle) * Math.cos(tilt);
            atoms[cid].z = a.z + BR * Math.sin(angle) * Math.cos(tilt);
            atoms[cid].y = a.y + BR * Math.sin(tilt) * zSign;
            placed.add(cid);
            queue.push({ id: cid, angle, depth: 1 });
        });
    });
    bfsBranch3D(atoms, adj, placed, queue, { bondLen: 1.8, decay: 0.06 });
}

// ============================================================
// Layout: Organic2 (original favorite)
// ============================================================
function layoutOrganic2(atoms, adj, ringArr, ringIds) {
    const BOND = 2.4;
    ringArr.forEach((id, i) => {
        const angle = (2 * Math.PI * i / ringArr.length) - Math.PI / 2;
        atoms[id].x = 2.0 * Math.cos(angle);
        atoms[id].y = 2.0 * Math.sin(angle);
        atoms[id].z = 0;
    });
    const placed = new Set(ringArr);
    const queue = [];
    ringArr.forEach((id, ri) => {
        const a = atoms[id];
        const outAngle = Math.atan2(a.y, a.x);
        const children = adj[id].filter(n => !placed.has(n));
        children.forEach((cid, ci) => {
            const n = children.length;
            const spread = Math.PI * 0.7;
            const xyAngle = n === 1 ? outAngle : outAngle - spread / 2 + spread * ci / (n - 1);
            const zOff = ((ci + ri) % 2 === 0 ? 1 : -1) * 0.4;
            atoms[cid].x = a.x + BOND * Math.cos(xyAngle);
            atoms[cid].y = a.y + BOND * Math.sin(xyAngle);
            atoms[cid].z = zOff;
            placed.add(cid);
            queue.push({ id: cid, inAngle: xyAngle, depth: 1, prevZ: zOff });
        });
    });
    while (queue.length > 0) {
        const { id, inAngle, depth, prevZ } = queue.shift();
        const children = adj[id].filter(n => !placed.has(n));
        if (!children.length) continue;
        const len = BOND * Math.max(0.8, 1 - depth * 0.06);
        children.forEach((cid, ci) => {
            const n = children.length;
            let angle;
            if (n === 1) angle = inAngle + (depth % 2 === 0 ? Math.PI / 5 : -Math.PI / 5);
            else { const spread = Math.min(Math.PI * 0.85, Math.PI * 0.25 * n); angle = inAngle - spread / 2 + spread * ci / (n - 1); }
            const zOff = -prevZ * 0.6;
            atoms[cid].x = atoms[id].x + len * Math.cos(angle);
            atoms[cid].y = atoms[id].y + len * Math.sin(angle);
            atoms[cid].z = atoms[id].z + zOff;
            placed.add(cid);
            queue.push({ id: cid, inAngle: angle, depth: depth + 1, prevZ: zOff });
        });
    }
}

// ============================================================
// Layout: Organic4 — organic2 + force polish to eliminate bunching
// ============================================================
function layoutOrganic4(atoms, adj, ringArr, ringIds) {
    layoutOrganic2(atoms, adj, ringArr, ringIds);
    forcePolish(atoms, ringIds, 60, 2.0);
}

// ============================================================
// Layout: Organic5 — wider ring, steeper zigzag, longer bonds
// ============================================================
function layoutOrganic5(atoms, adj, ringArr, ringIds) {
    const BOND = 2.6;
    ringArr.forEach((id, i) => {
        const angle = (2 * Math.PI * i / ringArr.length) - Math.PI / 2;
        atoms[id].x = 2.4 * Math.cos(angle);
        atoms[id].y = 2.4 * Math.sin(angle);
        atoms[id].z = 0;
    });
    const placed = new Set(ringArr);
    const queue = [];
    ringArr.forEach((id, ri) => {
        const a = atoms[id];
        const outAngle = Math.atan2(a.y, a.x);
        const children = adj[id].filter(n => !placed.has(n));
        children.forEach((cid, ci) => {
            const n = children.length;
            const spread = Math.PI * 0.8;
            const xyAngle = n === 1 ? outAngle : outAngle - spread / 2 + spread * ci / (n - 1);
            const zOff = ((ci + ri) % 2 === 0 ? 1 : -1) * 0.7; // steeper Z
            atoms[cid].x = a.x + BOND * Math.cos(xyAngle);
            atoms[cid].y = a.y + BOND * Math.sin(xyAngle);
            atoms[cid].z = zOff;
            placed.add(cid);
            queue.push({ id: cid, inAngle: xyAngle, depth: 1, prevZ: zOff });
        });
    });
    while (queue.length > 0) {
        const { id, inAngle, depth, prevZ } = queue.shift();
        const children = adj[id].filter(n => !placed.has(n));
        if (!children.length) continue;
        const len = BOND * Math.max(0.75, 1 - depth * 0.05);
        children.forEach((cid, ci) => {
            const n = children.length;
            let angle;
            if (n === 1) angle = inAngle + (depth % 2 === 0 ? Math.PI / 4 : -Math.PI / 4);
            else { const spread = Math.min(Math.PI * 0.9, Math.PI * 0.3 * n); angle = inAngle - spread / 2 + spread * ci / (n - 1); }
            const zOff = -prevZ * 0.7;
            atoms[cid].x = atoms[id].x + len * Math.cos(angle);
            atoms[cid].y = atoms[id].y + len * Math.sin(angle);
            atoms[cid].z = atoms[id].z + zOff;
            placed.add(cid);
            queue.push({ id: cid, inAngle: angle, depth: depth + 1, prevZ: zOff });
        });
    }
    forcePolish(atoms, ringIds, 40, 1.8);
}

// ============================================================
// Layout: Flat — organic2 projected to 2D (z=0), force polished
// ============================================================
function layoutFlat(atoms, adj, ringArr, ringIds) {
    layoutOrganic2(atoms, adj, ringArr, ringIds);
    // Flatten to 2D
    atoms.forEach(a => { a.z = 0; });
    // Force polish to spread out overlaps caused by flattening
    forcePolish(atoms, ringIds, 80, 2.2);
    atoms.forEach(a => { a.z = 0; }); // re-flatten after polish
}

// ============================================================
// Auto-fit camera to bounding box
// ============================================================
function autoFitCamera(group, camera, controls) {
    const box = new THREE.Box3().setFromObject(group);
    const center = box.getCenter(new THREE.Vector3());
    const sphere = box.getBoundingSphere(new THREE.Sphere());
    group.position.sub(center);
    controls.target.set(0, 0, 0);
    const fov = camera.fov * Math.PI / 180;
    const dist = sphere.radius / Math.sin(fov / 2) * 1.05;
    camera.position.set(dist * 0.5, dist * 0.35, dist * 0.75);
    camera.updateProjectionMatrix();
}

// ============================================================
// Rendering: atoms + bonds
// ============================================================

// Glossy materials for atoms
const bondGeoStd = new THREE.CylinderGeometry(0.055, 0.055, 1, 12);
const bondGeoBaseline = new THREE.CylinderGeometry(0.03, 0.03, 1, 6);
const bondMatStd = new THREE.MeshPhysicalMaterial({ color: 0xc0c0c0, roughness: 0.2, metalness: 0.5, clearcoat: 0.5 });
const bondMatBaseline = new THREE.MeshPhysicalMaterial({ color: 0x999999, roughness: 0.4, metalness: 0.2, transparent: true, opacity: 0.3 });

function addMolecule(atoms, bonds, group, moleculeIndex = null, molData = null) {
    // Pre-scan: identify cluster parents (atoms that have satellites) and all satellites.
    const clusterParents = new Set();
    const clusterSatellites = new Set();
    atoms.forEach((atom, i) => {
        if (atom.cluster_of) {
            clusterSatellites.add(i);
            clusterParents.add(atom.cluster_of - 1);
        }
    });

    atoms.forEach((atom, atomIndex) => {
        const color = severityColors[atom.severity] || severityColors.neutral;
        const bl = isBaseline(atom);
        const mat = new THREE.MeshPhysicalMaterial({
            color,
            roughness: bl ? 0.6 : 0.15,
            metalness: 0,
            clearcoat: bl ? 0 : 0.8,
            clearcoatRoughness: 0.1,
            transparent: bl,
            opacity: bl ? 0.4 : 1,
        });
        const geo = new THREE.SphereGeometry(atom.radius || 0.4, 32, 32);
        const mesh = new THREE.Mesh(geo, mat);
        mesh.position.set(atom.x, atom.y, atom.z);
        group.add(mesh);

        clickableMeshes.push(mesh);
        meshToMolecule.set(mesh, moleculeIndex);
        meshToAtom.set(mesh, { atom, moleculeData: molData });

        // Labels: show on normal atoms and cluster centers. Suppress on satellites.
        const isSatellite = clusterSatellites.has(atomIndex);
        if (atom.symbol && !isSatellite) {
            const labelDiv = document.createElement('div');
            labelDiv.className = 'atom-label' + (bl ? ' atom-label-baseline' : '');
            labelDiv.textContent = atom.symbol;
            const label = new CSS2DObject(labelDiv);
            label.position.set(0, 0, 0);
            mesh.add(label);
        }
    });

    if (bonds && bonds.length > 0) {
        bonds.forEach(bond => {
            const start = atoms[bond[0]];
            const end = atoms[bond[1]];
            if (!start || !end) return;

            const startVec = new THREE.Vector3(start.x, start.y, start.z);
            const endVec = new THREE.Vector3(end.x, end.y, end.z);
            const mid = new THREE.Vector3().addVectors(startVec, endVec).multiplyScalar(0.5);
            const length = startVec.distanceTo(endVec);

            const useBaseline = isBaseline(start) || isBaseline(end);
            const bondMesh = new THREE.Mesh(
                useBaseline ? bondGeoBaseline : bondGeoStd,
                useBaseline ? bondMatBaseline : bondMatStd
            );
            bondMesh.position.copy(mid);
            bondMesh.scale.y = length;
            bondMesh.lookAt(endVec);
            bondMesh.rotateX(Math.PI / 2);
            group.add(bondMesh);
        });
    }
}

// Extract basename from path
function basename(path) {
    if (path.includes('!!')) {
        path = path.split('!!').pop();
    }
    return path.split('/').pop();
}

// ============================================================
// Galaxy info panel
// ============================================================
const infoPanel = document.getElementById('galaxy-info');
const infoTitle = document.getElementById('galaxy-info-title');
const infoFormula = document.getElementById('galaxy-info-formula');
const infoFindings = document.getElementById('galaxy-info-findings');
const infoClose = document.getElementById('galaxy-info-close');

function showMoleculeInfo(mol) {
    infoTitle.textContent = basename(mol.path);
    infoFormula.textContent = mol.formula;

    const severity = mol.risk || 'notable';
    infoFindings.replaceChildren();
    if (mol.findings && mol.findings.length > 0) {
        mol.findings.forEach(f => {
            const div = document.createElement('div');
            div.className = severity;
            div.textContent = f;
            infoFindings.appendChild(div);
        });
    } else {
        const div = document.createElement('div');
        div.textContent = 'No findings';
        infoFindings.appendChild(div);
    }
    infoPanel.classList.add('visible');
}

// Traits lookup from molecule data (trait ID → {desc, crit, evidence[]})
const traitsLookup = moleculeData.traits || {};

function showAtomInfo(atom, mol) {
    if (atom.category === 'file') {
        const filename = moleculeData.filename || (mol ? basename(mol.path) : 'file');
        const fileType = moleculeData.fileType || (mol ? mol.formula : '');
        infoTitle.textContent = 'C \u00b7 ' + filename;
        infoFormula.textContent = fileType;
        infoFindings.replaceChildren();
        const div = document.createElement('div');
        div.className = 'dim';
        div.textContent = 'File root';
        infoFindings.appendChild(div);
        infoPanel.classList.add('visible');
        return;
    }

    const symbol = atom.symbol;
    const category = atom.category || 'unknown';
    const bl = isBaseline(atom);
    infoTitle.textContent = symbol + ' \u00b7 ' + category + (bl ? ' (baseline)' : '');
    infoFormula.textContent = '';

    infoFindings.replaceChildren();
    if (atom.trait_id) {
        // Deduplicate trait IDs
        const seen = new Set();
        const traitIds = atom.trait_id.split(', ').filter(t => {
            if (seen.has(t)) return false;
            seen.add(t);
            return true;
        });

        traitIds.forEach(tid => {
            const detail = traitsLookup[tid];
            const wrapper = document.createElement('div');
            wrapper.style.marginBottom = '6px';

            // Trait ID line
            const idLine = document.createElement('div');
            idLine.className = bl ? 'dim' : (atom.severity || 'notable');
            idLine.textContent = tid;
            wrapper.appendChild(idLine);

            if (detail) {
                // Description
                if (detail.desc) {
                    const descLine = document.createElement('div');
                    descLine.style.fontSize = '11px';
                    descLine.style.color = '#9ca3af';
                    descLine.textContent = detail.desc;
                    wrapper.appendChild(descLine);
                }
                // Evidence
                if (detail.evidence && detail.evidence.length > 0) {
                    detail.evidence.forEach(ev => {
                        const evLine = document.createElement('div');
                        evLine.style.fontSize = '10px';
                        evLine.style.color = '#6b7280';
                        evLine.textContent = '\u2192 ' + ev;
                        wrapper.appendChild(evLine);
                    });
                }
            }

            infoFindings.appendChild(wrapper);
        });
    } else {
        const div = document.createElement('div');
        div.className = 'dim';
        div.textContent = 'No specific traits';
        infoFindings.appendChild(div);
    }
    infoPanel.classList.add('visible');
}

if (infoClose) {
    infoClose.addEventListener('click', () => {
        infoPanel.classList.remove('visible');
    });
}

// ============================================================
// Raycaster for click/hover
// ============================================================
const raycaster = new THREE.Raycaster();
const mouse = new THREE.Vector2();

canvas.addEventListener('click', (event) => {
    const rect = canvas.getBoundingClientRect();
    mouse.x = ((event.clientX - rect.left) / rect.width) * 2 - 1;
    mouse.y = -((event.clientY - rect.top) / rect.height) * 2 + 1;

    raycaster.setFromCamera(mouse, camera);
    const intersects = raycaster.intersectObjects(clickableMeshes);

    if (intersects.length > 0) {
        const mesh = intersects[0].object;
        const atomData = meshToAtom.get(mesh);
        if (atomData) {
            showAtomInfo(atomData.atom, atomData.moleculeData);
        }
    }
});

canvas.addEventListener('mousemove', (event) => {
    const rect = canvas.getBoundingClientRect();
    mouse.x = ((event.clientX - rect.left) / rect.width) * 2 - 1;
    mouse.y = -((event.clientY - rect.top) / rect.height) * 2 + 1;

    raycaster.setFromCamera(mouse, camera);
    const intersects = raycaster.intersectObjects(clickableMeshes);
    canvas.style.cursor = intersects.length > 0 ? 'pointer' : 'default';
});

// ============================================================
// Build scene
// ============================================================
if (moleculeData && moleculeData.isGalaxy && moleculeData.molecules) {
    // Galaxy mode - multiple molecules for archives
    moleculeData.molecules.forEach((mol, molIndex) => {
        if (mol.atoms && mol.atoms.length > 0) {
            const cleanedBonds = cleanBonds(mol.bonds);
            applyLayout(mol.atoms, cleanedBonds, layout);
            // Offset back to galaxy position
            mol.atoms.forEach(a => { a.x += mol.centerX; a.y += mol.centerY; a.z += mol.centerZ; });
            addMolecule(mol.atoms, cleanedBonds, moleculeGroup, molIndex, mol);

            const labelDiv = document.createElement('div');
            labelDiv.className = 'molecule-label ' + (mol.risk || 'notable');
            labelDiv.textContent = basename(mol.path);
            const label = new CSS2DObject(labelDiv);
            label.position.set(mol.centerX, mol.centerY + 2.5, mol.centerZ);
            moleculeGroup.add(label);
        }
    });

    // Dropper relationship arrows
    if (moleculeData.links && moleculeData.links.length > 0) {
        const lineMat = new THREE.LineDashedMaterial({
            color: 0x22c55e, dashSize: 0.5, gapSize: 0.25, linewidth: 2
        });
        const arrowheadMat = new THREE.MeshStandardMaterial({
            color: 0x22c55e, roughness: 0.3, metalness: 0.1
        });
        const yAxis = new THREE.Vector3(0, 1, 0);

        moleculeData.links.forEach(link => {
            const fromMol = moleculeData.molecules[link.from];
            const toMol = moleculeData.molecules[link.to];
            if (!fromMol || !toMol) return;

            const start = new THREE.Vector3(fromMol.centerX, fromMol.centerY, fromMol.centerZ);
            const end = new THREE.Vector3(toMol.centerX, toMol.centerY, toMol.centerZ);
            const direction = new THREE.Vector3().subVectors(end, start);
            const length = direction.length();
            if (length < 1) return;

            const dir = direction.clone().normalize();
            const arrowheadLength = 0.6;
            const lineEnd = end.clone().sub(dir.clone().multiplyScalar(arrowheadLength));

            const geometry = new THREE.BufferGeometry().setFromPoints([start, lineEnd]);
            const line = new THREE.Line(geometry, lineMat);
            line.computeLineDistances();
            moleculeGroup.add(line);

            const coneGeo = new THREE.ConeGeometry(0.25, arrowheadLength, 12);
            const cone = new THREE.Mesh(coneGeo, arrowheadMat);
            cone.position.copy(end.clone().sub(dir.clone().multiplyScalar(arrowheadLength / 2)));
            const quaternion = new THREE.Quaternion();
            quaternion.setFromUnitVectors(yAxis, dir);
            cone.quaternion.copy(quaternion);
            moleculeGroup.add(cone);
        });
    }

    // Center + auto-fit galaxy
    autoFitCamera(moleculeGroup, camera, controls);

} else if (moleculeData && moleculeData.atoms && moleculeData.atoms.length > 0) {
    // Single molecule mode — apply layout then render
    const cleanedBonds = cleanBonds(moleculeData.bonds);
    applyLayout(moleculeData.atoms, cleanedBonds, layout);
    addMolecule(moleculeData.atoms, cleanedBonds, moleculeGroup);
    autoFitCamera(moleculeGroup, camera, controls);

} else {
    // No findings - show a simple neutral atom
    const mat = new THREE.MeshStandardMaterial({ color: 0x9ca3af, roughness: 0.3, metalness: 0.1 });
    const geo = new THREE.SphereGeometry(0.8, 32, 32);
    const mesh = new THREE.Mesh(geo, mat);
    moleculeGroup.add(mesh);
}

// Stop auto-rotate when user interacts
controls.addEventListener('start', () => {
    controls.autoRotate = false;
});

function animate() {
    requestAnimationFrame(animate);
    controls.update();
    renderer.render(scene, camera);
    labelRenderer.render(scene, camera);
}

animate();

window.addEventListener('resize', () => {
    camera.aspect = canvas.clientWidth / canvas.clientHeight;
    camera.updateProjectionMatrix();
    renderer.setSize(canvas.clientWidth, canvas.clientHeight);
    labelRenderer.setSize(canvas.clientWidth, canvas.clientHeight);
});

// Tab switching
document.querySelectorAll('.tab').forEach(tab => {
    tab.addEventListener('click', () => {
        document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
        document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
        tab.classList.add('active');
        document.getElementById('tab-' + tab.dataset.tab).classList.add('active');
    });
});
