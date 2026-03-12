const zone = document.getElementById('upload-zone');
const input = document.getElementById('file-input');
const btn = document.getElementById('submit-btn');
const uploadText = zone.querySelector('.upload-text');
const uploadHint = zone.querySelector('.upload-hint');
const uploadStatus = document.getElementById('upload-status');
const maxSize = 100 * 1024 * 1024; // 100 MB

['dragenter', 'dragover'].forEach(e => {
    zone.addEventListener(e, ev => {
        ev.preventDefault();
        zone.classList.add('dragover');
    });
});

['dragleave', 'drop'].forEach(e => {
    zone.addEventListener(e, ev => {
        ev.preventDefault();
        zone.classList.remove('dragover');
    });
});

zone.addEventListener('drop', e => {
    input.files = e.dataTransfer.files;
    updateUI();
});

input.addEventListener('change', updateUI);

document.getElementById('upload-form').addEventListener('submit', function() {
    btn.disabled = true;
    btn.textContent = 'Analyzing...';
    setTimeout(function() {
        uploadStatus.textContent = 'Waiting for analysis server to start up\u2026';
    }, 3000);
    setTimeout(function() {
        uploadStatus.textContent = 'Analysis server is starting up \u2014 this may take up to a minute.';
    }, 15000);
});

function updateUI() {
    if (input.files.length === 0) return;
    const file = input.files[0];
    uploadText.textContent = file.name;
    if (file.size > maxSize) {
        uploadHint.innerHTML = 'File exceeds 100 MB limit. For larger files, use <a href="https://codeberg.org/atomdrift/litmus" style="color: var(--isotope); text-decoration: underline">litmus CLI</a>';
        btn.disabled = true;
        zone.style.borderColor = 'var(--hostile)';
    } else {
        uploadHint.textContent = 'Binaries, source code, packages, archives';
        btn.disabled = false;
        zone.style.borderColor = '';
    }
}
