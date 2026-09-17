document.addEventListener("DOMContentLoaded", () => {
  const urlParams = new URLSearchParams(window.location.search);
  const targetUrl = urlParams.get('url');

  const urlDisplay = document.getElementById("url-display");
  if (targetUrl) {
    urlDisplay.textContent = targetUrl;
  } else {
    urlDisplay.textContent = "URL desconocida";
  }

  document.getElementById("btn-back").addEventListener("click", () => {
    if (window.history.length > 1) {
      window.history.back();
    } else {
      window.close();
      setTimeout(() => {
        window.location.href = "https://www.google.com";
      }, 100);
    }
  });

  document.getElementById("btn-continue").addEventListener("click", () => {
    if (targetUrl) {
      chrome.storage.local.get({ allowed_urls: [] }, (data) => {
        const allowed = data.allowed_urls;
        if (!allowed.includes(targetUrl)) {
          allowed.push(targetUrl);
        }
        chrome.storage.local.set({ allowed_urls: allowed }, () => {
          window.location.href = targetUrl;
        });
      });
    }
  });
});
