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

    // Simple upload (no loading bar)
    const form = document.getElementById('uploadForm');
    const uploadingMsg = document.getElementById('uploadingMsg');
    if (form && uploadingMsg) {
        form.addEventListener('submit', function () {
            uploadingMsg.style.display = 'block';
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
