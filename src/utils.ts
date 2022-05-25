export function isSmallTouchDevice() {
  const vh = Math.max(
    document.documentElement.clientHeight || 0,
    window.innerHeight || 0
  );
  return vh <= 760 && isTouchDevice();
}

/**
 * Taken from https://stackoverflow.com/questions/4817029/whats-the-best-way-to-detect-a-touch-screen-device-using-javascript
 **/
function isTouchDevice() {
  return "ontouchstart" in window || navigator.maxTouchPoints > 0;
}
