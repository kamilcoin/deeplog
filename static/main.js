document.addEventListener('DOMContentLoaded', function () {
    // Music button logic
    const bgMusic = document.getElementById('bgMusic');
    const musicBtn = document.getElementById('musicBtn');
    let isPlaying = true;
    if (musicBtn && bgMusic) {
        musicBtn.onclick = function () {
            if (isPlaying) {
                bgMusic.pause();
                musicBtn.textContent = "🔇 Music Off";
            } else {
                bgMusic.play();
                musicBtn.textContent = "🔊 Music On";
            }
            isPlaying = !isPlaying;
        };
        window.addEventListener('click', function playAudioOnce() {
            bgMusic.play();
            window.removeEventListener('click', playAudioOnce);
        });
    }

    // Progress-bar logic
    const form = document.getElementById('uploadForm');
    const progressBar = document.getElementById('progressBar');
    const progressContainer = document.getElementById('progressContainer');
    const progressLabel = document.getElementById('progressLabel');

    if (form && progressBar && progressContainer && progressLabel) {
        form.addEventListener('submit', function (e) {
            e.preventDefault();
            const fileInput = form.querySelector('input[type="file"]');
            if (!fileInput.files.length) return;
            const fileSize = fileInput.files[0].size;
            const minUploadDuration = 3000;
            const msPerMB = 500;
            const fileSizeMB = fileSize / (1024 * 1024);
            const uploadDuration = minUploadDuration + fileSizeMB * msPerMB;
            const analyzeDuration = 2000;

            progressContainer.style.display = 'block';
            progressLabel.style.display = 'block';
            progressBar.style.width = '0%';
            progressBar.textContent = '0%';
            progressLabel.textContent = 'Uploading...';

            const formData = new FormData(form);
            const xhr = new XMLHttpRequest();
            xhr.open('POST', form.action, true);
            let percent = 0;
            const uploadSteps = 99;
            const uploadStepTime = uploadDuration / uploadSteps;
            const uploadInterval = setInterval(() => {
                if (percent < 99) {
                    percent += 1;
                    progressBar.style.width = percent + '%';
                    progressBar.textContent = percent + '%';
                }
            }, uploadStepTime);

            xhr.onload = function () {
                clearInterval(uploadInterval);
                progressLabel.textContent = 'Analyzing...';
                let analyzePercent = percent;
                const analyzeSteps = 100 - analyzePercent;
                const analyzeStepTime = analyzeDuration / analyzeSteps;
                const analyzeInterval = setInterval(() => {
                    analyzePercent += 1;
                    progressBar.style.width = analyzePercent + '%';
                    progressBar.textContent = analyzePercent + '%';
                    if (analyzePercent >= 100) {
                        clearInterval(analyzeInterval);
                        progressLabel.textContent = 'Completed!';
                        setTimeout(() => {
                            document.open();
                            document.write(xhr.responseText);
                            document.close();
                        }, 800);
                    }
                }, analyzeStepTime);
            };
            xhr.onerror = function () {
                clearInterval(uploadInterval);
                progressLabel.textContent = 'Upload failed.';
            };
            xhr.send(formData);
        });
    }

    // Donation popup logic
    const donateBtn = document.getElementById('donateBtn');
    const donateModal = document.getElementById('donateModal');
    const donateClose = document.getElementById('donateClose');
    if (donateBtn && donateModal && donateClose) {
        donateBtn.onclick = () => donateModal.style.display = 'flex';
        donateClose.onclick = () => donateModal.style.display = 'none';
        window.onclick = (e) => {
            if (e.target == donateModal) donateModal.style.display = 'none';
        };
    }

    // Copy button logic
    document.querySelectorAll('.copy-btn').forEach(btn => {
        btn.onclick = function () {
            const value = btn.getAttribute('data-copy');
            navigator.clipboard.writeText(value);
            const msg = document.getElementById('donateCopyMsg');
            if (msg) {
                msg.innerText = "Copied!";
                msg.style.opacity = "1";
                setTimeout(() => { msg.style.opacity = "0"; }, 1300);
            }
        }
    });
});