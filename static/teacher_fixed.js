// Minimal patch for teacher dashboard:
// - Fix /api/announce call
// - Fix /api/scenes/apply & disableScene
// Everything else is left untouched.

(function(){
  function $(sel){ return document.querySelector(sel); }

  function safeFetch(url, opts){
    opts = opts || {};
    const baseHeaders = { "Content-Type": "application/json" };
    if (!opts.headers) opts.headers = baseHeaders;
    else opts.headers = Object.assign({}, baseHeaders, opts.headers);
    return fetch(url, opts);
  }

  function toast(msg){
    if (window.toast) return window.toast(msg);
    if (window.showToast) return window.showToast(msg);
    console.log("[GSchool teacher]", msg);
  }

  document.addEventListener("DOMContentLoaded", () => {
    // ---------- Announcements ----------
    const announceBtn = document.getElementById("announceBtn");
    if (announceBtn){
      announceBtn.addEventListener("click", async () => {
        const msg = prompt("Announcement to show on student screens:");
        if (msg === null) return;
        try{
          await safeFetch("/api/announce", {
            method: "POST",
            body: JSON.stringify({ message: msg })
          });
          toast("Announcement sent");
        }catch(e){
          console.error("announce failed", e);
          alert("Announcement failed to send");
        }
      });
    }

    // ---------- Scenes ----------
    async function applySceneFixed(id){
      if (!id) return;
      const dd = document.getElementById("sceneDropdown");
      if (dd && dd.classList) dd.classList.remove("open");
      if (window.showOverlay) window.showOverlay();
      try{
        const r = await safeFetch("/api/scenes/apply", {
          method: "POST",
          body: JSON.stringify({ scene_id: id })
        });
        if (r.ok){
          toast("Scene applied");
        } else {
          alert("Failed to apply scene");
        }
      }catch(e){
        console.error("applyScene", e);
        alert("Failed to apply scene");
      }finally{
        if (window.hideOverlay) window.hideOverlay();
        if (window.loadScenes) window.loadScenes();
      }
    }

    async function disableSceneFixed(){
      const dd = document.getElementById("sceneDropdown");
      if (dd && dd.classList) dd.classList.remove("open");
      if (window.showOverlay) window.showOverlay();
      try{
        const r = await safeFetch("/api/scenes/apply", {
          method: "POST",
          body: JSON.stringify({ disable: true })
        });
        if (r.ok){
          toast("Scene disabled");
        } else {
          alert("Failed to disable scene");
        }
      }catch(e){
        console.error("disableScene", e);
        alert("Failed to disable scene");
      }finally{
        if (window.hideOverlay) window.hideOverlay();
        if (window.loadScenes) window.loadScenes();
      }
    }

    // Expose globals so existing HTML onclick handlers keep working
    window.applyScene = applySceneFixed;
    window.disableScene = disableSceneFixed;
  });
})();