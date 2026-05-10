const input = document.getElementById('file-input');
const form = document.getElementById('upload-form');
const uploadStatus = document.getElementById('upload-status');
const filterForm = document.getElementById('filter-form');
const criticalityFilter = document.getElementById('criticality');
const ecosystemFilter = document.getElementById('ecosystem-filter');
const domainFilter = document.getElementById('domain-filter');
const maxSize = 100 * 1024 * 1024; // 100 MB

document.querySelectorAll('[data-gradient]').forEach(el => { el.style.background = el.getAttribute('data-gradient'); });

function setStatusText(message, className = '') {
    uploadStatus.className = 'top-upload-status' + (className ? ' ' + className : '');
    uploadStatus.textContent = message;
}

function setAnalyzingStatus(fileName) {
    uploadStatus.className = 'top-upload-status is-analyzing';
    uploadStatus.innerHTML = '<span class="analyzing-label">Analyzing</span><span class="analyzing-dots" aria-hidden="true"><span></span><span></span><span></span></span> <span class="analyzing-file"></span>';
    uploadStatus.querySelector('.analyzing-file').textContent = fileName;
}

if (ecosystemFilter) {
    ecosystemFilter.addEventListener('change', function() {
        const url = new URL(window.location.origin + (ecosystemFilter.value ? '/' + encodeURIComponent(ecosystemFilter.value) + '/' : '/'));
        if (criticalityFilter && criticalityFilter.value) {
            url.searchParams.set('criticality', criticalityFilter.value);
        }
        if (domainFilter && domainFilter.value) {
            url.searchParams.set('domain', domainFilter.value);
        }
        window.location = url.toString();
    });
}

if (criticalityFilter && filterForm) {
    criticalityFilter.addEventListener('change', function() {
        filterForm.submit();
    });
}

if (domainFilter && filterForm) {
    domainFilter.addEventListener('change', function() {
        filterForm.submit();
    });
}

if (input && form) {
    input.addEventListener('change', function() {
        if (input.files.length === 0) return;
        const file = input.files[0];
        if (file.size > maxSize) {
            uploadStatus.className = 'top-upload-status';
            uploadStatus.innerHTML = 'File exceeds 100 MB. Use <a href="https://codeberg.org/atomdrift/litmus">litmus CLI</a>.';
            input.value = '';
            return;
        }
        setAnalyzingStatus(file.name);
        form.submit();
    });

    form.addEventListener('submit', function() {
        setTimeout(function() {
            setStatusText('Waiting for analysis server to start up...');
        }, 3000);
        setTimeout(function() {
            setStatusText('Analysis server is starting up; this may take up to a minute.');
        }, 15000);
    });
}
