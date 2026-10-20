{{flutter_js}}
{{flutter_build_config}}

(async function () {
  const appBase = new URL('./', document.baseURI);
  const ownWorker = new URL('flutter_service_worker.js', appBase).href;
  try {
    if ('serviceWorker' in navigator) {
      const registrations = await navigator.serviceWorker.getRegistrations();
      await Promise.all(registrations.filter((registration) =>
        registration.scope === appBase.href &&
        [registration.active, registration.waiting, registration.installing]
          .some((worker) => worker && worker.scriptURL === ownWorker)
      ).map((registration) => registration.unregister()));
    }

    if ('caches' in window) {
      const names = await caches.keys();
      for (const name of names.filter((entry) =>
        ['flutter-app-cache', 'flutter-temp-cache', 'flutter-app-manifest'].includes(entry)
      )) {
        const cache = await caches.open(name);
        const requests = await cache.keys();
        await Promise.all(requests.filter((request) => {
          const url = new URL(request.url);
          return url.origin === appBase.origin && url.pathname.startsWith(appBase.pathname);
        }).map((request) => cache.delete(request)));
      }
    }
  } catch (error) {
    console.warn('Failed to clear this app’s old Flutter cache:', error);
  }

  _flutter.loader.load();
})();
