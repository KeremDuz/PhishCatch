{{flutter_js}}
{{flutter_build_config}}

(async function () {
  try {
    if ('serviceWorker' in navigator) {
      const registrations = await navigator.serviceWorker.getRegistrations();
      await Promise.all(registrations.map((registration) => registration.unregister()));
    }

    if ('caches' in window) {
      const cacheNames = await caches.keys();
      await Promise.all(cacheNames.map((cacheName) => caches.delete(cacheName)));
    }
  } catch (error) {
    console.warn('Failed to clear old Flutter web cache:', error);
  }

  const cacheBuster = Date.now().toString();
  for (const build of _flutter.buildConfig.builds) {
    if (build.mainJsPath) {
      build.mainJsPath = `${build.mainJsPath}?v=${cacheBuster}`;
    }
  }

  _flutter.loader.load();
})();
