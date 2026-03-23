import * as THREE from '/static/js/three.module.js';
import { CSS2DRenderer, CSS2DObject } from '/static/js/CSS2DRenderer.js';
import { OrbitControls } from '/static/js/OrbitControls.js';

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
    hostile: 0xef4444,
    suspicious: 0xeab308,
    notable: 0x3b82f6,
    neutral: 0x9ca3af
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

    const adj = buildAdj(atoms, bonds);
    const ringArr = [];
    atoms.forEach((a, i) => { if (a.ring) ringArr.push(i); });
    if (ringArr.length === 0) return; // nothing to layout
    const ringIds = new Set(ringArr);

    switch (layoutName) {
    case 'helix':
        layoutHelix(atoms, adj, ringArr, ringIds);
        break;
    case 'organic':
        layoutOrganic(atoms, adj, ringArr, ringIds);
        break;
    case 'tetrahedral':
    default:
        layoutTetrahedral(atoms, adj, ringArr, ringIds);
        break;
    }

    // Center result
    let cx = 0, cy = 0, cz = 0;
    atoms.forEach(a => { cx += a.x; cy += a.y; cz += a.z; });
    cx /= atoms.length; cy /= atoms.length; cz /= atoms.length;
    atoms.forEach(a => { a.x -= cx; a.y -= cy; a.z -= cz; });
}

// --- Tetrahedral: flat ring, branches at 109.5° alternating above/below ---
function layoutTetrahedral(atoms, adj, ringArr, ringIds) {
    const BOND = 2.2;
    const N = atoms.length;

    // Ring flat in XY
    ringArr.forEach((id, i) => {
        const angle = (2 * Math.PI * i / ringArr.length) - Math.PI / 2;
        atoms[id].x = 2 * Math.cos(angle);
        atoms[id].y = 2 * Math.sin(angle);
        atoms[id].z = 0;
    });

    const placed = new Set(ringArr);
    const queue = [];

    // Branch from ring with tetrahedral angles
    ringArr.forEach(id => {
        const a = atoms[id];
        const outAngle = Math.atan2(a.y, a.x);
        const children = adj[id].filter(n => !placed.has(n));
        children.forEach((cid, ci) => {
            const n = children.length;
            const spread = Math.PI * 0.65;
            const xyAngle = n === 1 ? outAngle : outAngle - spread / 2 + spread * ci / (n - 1);
            const zSign = (ci % 2 === 0) ? 1 : -1;
            const tilt = Math.PI / 5;
            atoms[cid].x = a.x + BOND * Math.cos(xyAngle) * Math.cos(tilt);
            atoms[cid].y = a.y + BOND * Math.sin(xyAngle) * Math.cos(tilt);
            atoms[cid].z = a.z + BOND * Math.sin(tilt) * zSign;
            placed.add(cid);
            queue.push({ id: cid, inAngle: xyAngle, depth: 1 });
        });
    });

    while (queue.length > 0) {
        const { id, inAngle, depth } = queue.shift();
        const children = adj[id].filter(n => !placed.has(n));
        if (!children.length) continue;
        const len = BOND * Math.max(0.65, 1 - depth * 0.12);
        children.forEach((cid, ci) => {
            const n = children.length;
            let xyAngle;
            if (n === 1) xyAngle = inAngle + ((depth % 2) ? 0.25 : -0.25);
            else { const s = Math.PI * 0.4; xyAngle = inAngle - s / 2 + s * ci / (n - 1); }
            const zSign = ((ci + depth) % 2 === 0) ? 1 : -1;
            const tilt = Math.PI / 6;
            atoms[cid].x = atoms[id].x + len * Math.cos(xyAngle) * Math.cos(tilt);
            atoms[cid].y = atoms[id].y + len * Math.sin(xyAngle) * Math.cos(tilt);
            atoms[cid].z = atoms[id].z + len * Math.sin(tilt) * zSign;
            placed.add(cid);
            queue.push({ id: cid, inAngle: xyAngle, depth: depth + 1 });
        });
    }

    // Light repulsion relaxation to prevent overlap
    const vel = atoms.map(() => ({ x: 0, y: 0, z: 0 }));
    for (let iter = 0; iter < 100; iter++) {
        for (let i = 0; i < N; i++) {
            if (ringIds.has(i)) continue;
            for (let j = i + 1; j < N; j++) {
                if (ringIds.has(j)) continue;
                const dx = atoms[i].x - atoms[j].x, dy = atoms[i].y - atoms[j].y, dz = atoms[i].z - atoms[j].z;
                const d = Math.sqrt(dx * dx + dy * dy + dz * dz) || 0.01;
                if (d < 1.5) {
                    const f = 0.3 * (1.5 - d);
                    vel[i].x += dx / d * f; vel[i].y += dy / d * f; vel[i].z += dz / d * f;
                    vel[j].x -= dx / d * f; vel[j].y -= dy / d * f; vel[j].z -= dz / d * f;
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

// --- Helix: ring atoms spiral upward, branches radiate outward ---
function layoutHelix(atoms, adj, ringArr, ringIds) {
    const HR = 1.8, HP = 3.0, TURNS = 0.28, BR = 2.2;

    ringArr.forEach((id, i) => {
        const t = i * TURNS * 2 * Math.PI;
        atoms[id].x = HR * Math.cos(t);
        atoms[id].z = HR * Math.sin(t);
        atoms[id].y = i * HP * TURNS;
    });
    const helixMidY = (ringArr.length - 1) * HP * TURNS / 2;
    ringArr.forEach(id => { atoms[id].y -= helixMidY; });

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

    while (queue.length > 0) {
        const { id, angle, depth } = queue.shift();
        const children = adj[id].filter(n => !placed.has(n));
        if (!children.length) continue;
        const len = 1.6 * Math.max(0.6, 1 - depth * 0.15);
        children.forEach((cid, ci) => {
            const n = children.length;
            let a2;
            if (n === 1) a2 = angle + (depth % 2 ? 0.3 : -0.3);
            else { const s = Math.PI * 0.4; a2 = angle - s / 2 + s * ci / (n - 1); }
            const zSign = ((ci + depth) % 2 === 0) ? 1 : -1;
            const tilt = Math.PI / 6;
            atoms[cid].x = atoms[id].x + len * Math.cos(a2) * Math.cos(tilt);
            atoms[cid].z = atoms[id].z + len * Math.sin(a2) * Math.cos(tilt);
            atoms[cid].y = atoms[id].y + len * Math.sin(tilt) * zSign * 0.5;
            placed.add(cid);
            queue.push({ id: cid, angle: a2, depth: depth + 1 });
        });
    }
}

// --- Organic: flat ring, 3D zigzag branches at 120° angles ---
function layoutOrganic(atoms, adj, ringArr, ringIds) {
    const BOND = 2.0;

    ringArr.forEach((id, i) => {
        const angle = (2 * Math.PI * i / ringArr.length) - Math.PI / 2;
        atoms[id].x = 1.6 * Math.cos(angle);
        atoms[id].y = 1.6 * Math.sin(angle);
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
            const spread = Math.PI * 0.6;
            const xyAngle = n === 1 ? outAngle : outAngle - spread / 2 + spread * ci / (n - 1);
            const zOff = ((ci + ri) % 2 === 0 ? 1 : -1) * 0.8;
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
        const len = BOND * Math.max(0.7, 1 - depth * 0.1);
        children.forEach((cid, ci) => {
            const n = children.length;
            let angle;
            if (n === 1) {
                angle = inAngle + (depth % 2 === 0 ? Math.PI / 6 : -Math.PI / 6);
            } else {
                const spread = Math.PI * 0.45;
                angle = inAngle - spread / 2 + spread * ci / (n - 1);
            }
            const zOff = -prevZ * 0.8;
            atoms[cid].x = atoms[id].x + len * Math.cos(angle);
            atoms[cid].y = atoms[id].y + len * Math.sin(angle);
            atoms[cid].z = atoms[id].z + zOff;
            placed.add(cid);
            queue.push({ id: cid, inAngle: angle, depth: depth + 1, prevZ: zOff });
        });
    }
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

        if (atom.symbol) {
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
    const baseline = isBaseline(atom);
    infoTitle.textContent = symbol + ' \u00b7 ' + category + (baseline ? ' (baseline)' : '');
    infoFormula.textContent = mol ? basename(mol.path) : '';

    const severity = baseline ? 'dim' : (atom.severity || 'notable');
    infoFindings.replaceChildren();
    if (atom.trait_id) {
        atom.trait_id.split(', ').forEach(t => {
            const div = document.createElement('div');
            div.className = severity;
            div.textContent = t;
            infoFindings.appendChild(div);
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
