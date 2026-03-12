import * as THREE from '/static/js/three.module.js';
import { CSS2DRenderer, CSS2DObject } from '/static/js/CSS2DRenderer.js';
import { OrbitControls } from '/static/js/OrbitControls.js';

// Molecule data injected by Go template into a JSON script tag
const moleculeData = JSON.parse(document.getElementById('molecule-data').textContent);

const canvas = document.getElementById('molecule-canvas');
if (!canvas) throw new Error('Canvas not found');

const scene = new THREE.Scene();
const camera = new THREE.PerspectiveCamera(50, canvas.clientWidth / canvas.clientHeight, 0.1, 1000);
// Default camera position for single molecule (flat diagram, slight elevation)
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
const ambientLight = new THREE.AmbientLight(0xffffff, 0.5);
scene.add(ambientLight);

const directionalLight = new THREE.DirectionalLight(0xffffff, 1);
directionalLight.position.set(5, 5, 5);
scene.add(directionalLight);

const backLight = new THREE.DirectionalLight(0xffffff, 0.3);
backLight.position.set(-5, -5, -5);
scene.add(backLight);

const moleculeGroup = new THREE.Group();
scene.add(moleculeGroup);

// Color mapping for severity
const severityColors = {
    hostile: 0xef4444,
    suspicious: 0xeab308,
    notable: 0x3b82f6,
    neutral: 0x9ca3af
};

// Bond materials: standard for notable+ connections, dim for baseline connections
const bondMat = new THREE.MeshStandardMaterial({ color: 0x6b7280, roughness: 0.5, metalness: 0.0 });
const bondMatBaseline = new THREE.MeshStandardMaterial({ color: 0x4b5563, roughness: 0.7, metalness: 0.0, transparent: true, opacity: 0.35 });

// Track clickable meshes for raycasting
const clickableMeshes = [];
const meshToMolecule = new Map();
const meshToAtom = new Map();

// Returns true if this atom is a dim supporting/neutral atom.
// Ring atoms (inner hexagonal ring) and the file fallback atom are always opaque.
function isBaseline(atom) {
    return atom.severity === 'neutral' && !atom.ring && atom.category !== 'file';
}

// Helper to add atoms and bonds to scene
function addMolecule(atoms, bonds, group, moleculeIndex = null, molData = null) {
    atoms.forEach((atom, atomIndex) => {
        const color = severityColors[atom.severity] || severityColors.neutral;
        const mat = isBaseline(atom)
            ? new THREE.MeshStandardMaterial({ color, roughness: 0.6, metalness: 0.0, transparent: true, opacity: 0.45 })
            : new THREE.MeshStandardMaterial({ color, roughness: 0.3, metalness: 0.1 });
        const geo = new THREE.SphereGeometry(atom.radius || 0.4, 16, 16);
        const mesh = new THREE.Mesh(geo, mat);
        mesh.position.set(atom.x, atom.y, atom.z);
        group.add(mesh);

        // Always track atoms for raycasting (single molecule + galaxy)
        clickableMeshes.push(mesh);
        meshToMolecule.set(mesh, moleculeIndex);
        meshToAtom.set(mesh, { atom, moleculeData: molData });

        // Element symbol label on each atom
        if (atom.symbol) {
            const labelDiv = document.createElement('div');
            labelDiv.className = 'atom-label' + (isBaseline(atom) ? ' atom-label-baseline' : '');
            labelDiv.textContent = atom.symbol;
            const label = new CSS2DObject(labelDiv);
            label.position.set(0, 0, 0);
            mesh.add(label);
        }
    });

    if (bonds && bonds.length > 0) {
        const bondGeoStd      = new THREE.CylinderGeometry(0.05, 0.05, 1, 8);
        const bondGeoBaseline = new THREE.CylinderGeometry(0.03, 0.03, 1, 6);
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
                useBaseline ? bondMatBaseline : bondMat
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

// Galaxy info panel
const infoPanel = document.getElementById('galaxy-info');
const infoTitle = document.getElementById('galaxy-info-title');
const infoFormula = document.getElementById('galaxy-info-formula');
const infoFindings = document.getElementById('galaxy-info-findings');
const infoClose = document.getElementById('galaxy-info-close');

function showMoleculeInfo(mol) {
    infoTitle.textContent = basename(mol.path);
    infoFormula.textContent = mol.formula;

    // Use mol.risk for severity coloring
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
    // File center atom: show filename and file type
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
    // Category is the node key (e.g. "execution", "network") — show it directly
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

// Raycaster for click detection
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

// Change cursor on hover
canvas.addEventListener('mousemove', (event) => {
    const rect = canvas.getBoundingClientRect();
    mouse.x = ((event.clientX - rect.left) / rect.width) * 2 - 1;
    mouse.y = -((event.clientY - rect.top) / rect.height) * 2 + 1;

    raycaster.setFromCamera(mouse, camera);
    const intersects = raycaster.intersectObjects(clickableMeshes);

    canvas.style.cursor = intersects.length > 0 ? 'pointer' : 'default';
});

// Parse molecule data and create visualization
if (moleculeData && moleculeData.isGalaxy && moleculeData.molecules) {
    // Galaxy mode - multiple molecules for archives
    camera.position.set(0, 6, 25); // Zoom out for galaxy view

    moleculeData.molecules.forEach((mol, molIndex) => {
        if (mol.atoms && mol.atoms.length > 0) {
            addMolecule(mol.atoms, mol.bonds, moleculeGroup, molIndex, mol);

            // Add label for this molecule
            const labelDiv = document.createElement('div');
            labelDiv.className = 'molecule-label ' + (mol.risk || 'notable');
            labelDiv.textContent = basename(mol.path);
            const label = new CSS2DObject(labelDiv);
            label.position.set(mol.centerX, mol.centerY + 2.5, mol.centerZ);
            moleculeGroup.add(label);
        }
    });

    // Add dropper relationship arrows (dashed green lines)
    if (moleculeData.links && moleculeData.links.length > 0) {
        const lineMat = new THREE.LineDashedMaterial({
            color: 0x22c55e,
            dashSize: 0.5,
            gapSize: 0.25,
            linewidth: 2
        });

        const arrowheadMat = new THREE.MeshStandardMaterial({
            color: 0x22c55e,
            roughness: 0.3,
            metalness: 0.1
        });

        // Helper to align a cone along a direction
        const yAxis = new THREE.Vector3(0, 1, 0);
        function alignToDirection(mesh, direction) {
            const quaternion = new THREE.Quaternion();
            quaternion.setFromUnitVectors(yAxis, direction.clone().normalize());
            mesh.quaternion.copy(quaternion);
        }

        moleculeData.links.forEach(link => {
            const fromMol = moleculeData.molecules[link.from];
            const toMol = moleculeData.molecules[link.to];
            if (!fromMol || !toMol) return;

            // Connect directly to molecule centers
            const start = new THREE.Vector3(fromMol.centerX, fromMol.centerY, fromMol.centerZ);
            const end = new THREE.Vector3(toMol.centerX, toMol.centerY, toMol.centerZ);
            const direction = new THREE.Vector3().subVectors(end, start);
            const length = direction.length();

            if (length < 1) return;

            const dir = direction.clone().normalize();
            // Pull back the end point slightly for the arrowhead
            const arrowheadLength = 0.6;
            const lineEnd = end.clone().sub(dir.clone().multiplyScalar(arrowheadLength));

            // Dashed line from center to center
            const points = [start, lineEnd];
            const geometry = new THREE.BufferGeometry().setFromPoints(points);
            const line = new THREE.Line(geometry, lineMat);
            line.computeLineDistances(); // Required for dashed lines
            moleculeGroup.add(line);

            // Arrowhead (cone) at the end
            const coneGeo = new THREE.ConeGeometry(0.25, arrowheadLength, 12);
            const cone = new THREE.Mesh(coneGeo, arrowheadMat);
            cone.position.copy(end.clone().sub(dir.clone().multiplyScalar(arrowheadLength / 2)));
            alignToDirection(cone, dir);
            moleculeGroup.add(cone);
        });
    }

    // Center the galaxy
    const box = new THREE.Box3().setFromObject(moleculeGroup);
    const center = box.getCenter(new THREE.Vector3());
    moleculeGroup.position.sub(center);
} else if (moleculeData && moleculeData.atoms && moleculeData.atoms.length > 0) {
    // Single molecule mode
    addMolecule(moleculeData.atoms, moleculeData.bonds, moleculeGroup);

    // Center the molecule
    const box = new THREE.Box3().setFromObject(moleculeGroup);
    const center = box.getCenter(new THREE.Vector3());
    moleculeGroup.position.sub(center);
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
