const fs = require('fs');

let css = fs.readFileSync('public/styles.css', 'utf8');

// Replace corrupted floating toggle
const fixToggleRegex = /\. f l o a t i n g - t h e m e - t o g g l e[\s\S]*/;
css = css.replace(fixToggleRegex, `
.floating-theme-toggle {
  position: fixed;
  bottom: 32px;
  right: 32px;
  width: 64px;
  height: 64px;
  border-radius: 50%;
  background: var(--panel);
  border: 1px solid var(--border);
  box-shadow: var(--shadow-lg);
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 32px;
  cursor: pointer;
  z-index: 9999;
  backdrop-filter: blur(16px);
  color: var(--ink);
  transition: transform 0.2s, box-shadow 0.2s;
}
.floating-theme-toggle:hover {
  transform: translateY(-4px) scale(1.05);
  box-shadow: 0 25px 50px -12px rgba(0,0,0,0.25);
}
`);

fs.writeFileSync('public/styles.css', css);
