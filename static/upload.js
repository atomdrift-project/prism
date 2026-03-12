const zone = document.getElementById('upload-zone');
const input = document.getElementById('file-input');
const btn = document.getElementById('submit-btn');
const uploadText = zone.querySelector('.upload-text');

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

function updateUI() {
    if (input.files.length > 0) {
        uploadText.textContent = input.files[0].name;
        btn.disabled = false;
    }
}
