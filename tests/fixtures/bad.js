// Deliberate-bad sample for cyscan integration tests.

const el = document.getElementById('bio')
function render(userBio) {
  // CBR-JS-XSS-INNER-HTML
  el.innerHTML = userBio
}
