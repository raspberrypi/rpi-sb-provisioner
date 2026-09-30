// One way to upload a file, for signing keys and OS images alike: an Add
// button opens a panel, and a file is dropped on it or chosen with its
// button, which the keyboard reaches as well as the mouse.
(function () {
    'use strict';

    // opts: toggle (the Add button), panel, zone, input, onFile(file).
    // Returns open(), close() and busy(on) for the page to call.
    function attach(opts) {
        const { toggle, panel, zone, input, onFile } = opts;
        const choose = zone.querySelector('.upload-choose');

        function open() {
            panel.style.display = 'block';
            if (toggle) toggle.setAttribute('aria-expanded', 'true');
        }
        function close() {
            panel.style.display = 'none';
            if (toggle) toggle.setAttribute('aria-expanded', 'false');
        }
        function busy(on) {
            zone.classList.toggle('busy', on);
            if (choose) choose.disabled = on;
        }
        function take(files) {
            if (files && files.length > 0 && !zone.classList.contains('busy')) onFile(files[0]);
        }

        if (toggle) {
            toggle.setAttribute('aria-controls', panel.id);
            toggle.setAttribute('aria-expanded', panel.style.display === 'none' ? 'false' : 'true');
            toggle.addEventListener('click', function () {
                if (panel.style.display === 'none') open(); else close();
            });
        }
        if (choose) choose.addEventListener('click', function () { input.click(); });
        zone.addEventListener('click', function (e) {
            if (e.target === zone && !zone.classList.contains('busy')) input.click();
        });
        zone.addEventListener('dragover', function (e) { e.preventDefault(); zone.classList.add('dragover'); });
        zone.addEventListener('dragleave', function () { zone.classList.remove('dragover'); });
        zone.addEventListener('drop', function (e) {
            e.preventDefault();
            zone.classList.remove('dragover');
            take(e.dataTransfer.files);
        });
        input.addEventListener('change', function () {
            take(input.files);
            input.value = '';
        });
        return { open: open, close: close, busy: busy };
    }

    window.RpiUpload = { attach: attach };
})();
