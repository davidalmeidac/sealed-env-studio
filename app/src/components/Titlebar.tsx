import { getCurrentWindow } from '@tauri-apps/api/window';

const win = getCurrentWindow();

export function Titlebar() {
  return (
    <div className="titlebar" data-tauri-drag-region>
      <div className="titlebar__brand" data-tauri-drag-region>
        <span className="titlebar__sigil">SE</span>
        <span className="titlebar__title">sealed-env Studio</span>
      </div>
      <div className="titlebar__controls">
        <button
          className="titlebar__btn"
          aria-label="Minimize"
          title="Minimize"
          onClick={() => { void win.minimize(); }}
        >
          &#x2014;
        </button>
        <button
          className="titlebar__btn"
          aria-label="Toggle maximize"
          title="Maximize"
          onClick={() => { void win.toggleMaximize(); }}
        >
          &#x25A2;
        </button>
        <button
          className="titlebar__btn titlebar__btn--close"
          aria-label="Close"
          title="Close"
          onClick={() => { void win.close(); }}
        >
          &#x2715;
        </button>
      </div>
    </div>
  );
}
