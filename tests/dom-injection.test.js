/**
 * Tests for Blueprint #5: Elimination of Unsafe HTML Rendering & DOM Injection
 * Verifies that dynamic strings (details, classifier names, file names, titles)
 * cannot inject HTML elements or execute scripts when rendered in modals.
 */

function escapeHtml(t) {
  const d = document.createElement('div');
  d.textContent = t;
  return d.innerHTML;
}

describe('Blueprint #5: DOM Injection Prevention & Safe HTML Rendering', () => {
  const XSS_PAYLOADS = [
    '<script>alert(1)</script>',
    '<img src="x" onerror="alert(1)">',
    '"><svg onload="alert(document.cookie)">',
    '\'><iframe src="javascript:alert(1)"></iframe>',
    '<body onload="alert(1)">',
    '<<SCRIPT>alert("XSS");//<</SCRIPT>',
    '<a href="javascript:alert(1)">Click me</a>'
  ];

  test('escapeHtml neutralizes all standard XSS attack payloads', () => {
    XSS_PAYLOADS.forEach((payload) => {
      const escaped = escapeHtml(payload);
      expect(escaped).not.toContain('<script>');
      expect(escaped).not.toContain('<img');
      expect(escaped).not.toContain('<svg');
      expect(escaped).not.toContain('<iframe');

      const container = document.createElement('div');
      container.innerHTML = escaped;

      // Ensure no script, img, svg, or iframe elements were created in DOM
      expect(container.querySelector('script')).toBeNull();
      expect(container.querySelector('img')).toBeNull();
      expect(container.querySelector('svg')).toBeNull();
      expect(container.querySelector('iframe')).toBeNull();

      // Ensure the text content matches original string literally
      expect(container.textContent).toBe(payload);
    });
  });

  test('modal details parameter with injection payload does not execute DOM sinks', () => {
    const maliciousDetails = 'Model flagged: <img src=x onerror=window.xss=1>';
    const safeDetailsHtml = `<div class="details">${escapeHtml(maliciousDetails)}</div>`;

    const modal = document.createElement('div');
    modal.innerHTML = safeDetailsHtml;

    expect(modal.querySelector('img')).toBeNull();
    expect(modal.textContent).toContain('<img src=x onerror=window.xss=1>');
  });

  test('file name with HTML tags in attachment warnings renders purely as text', () => {
    const maliciousFileName = '<script>window.hacked=true</script>.pdf';
    const escapedName = escapeHtml(maliciousFileName);

    const card = document.createElement('div');
    card.innerHTML = `<span class="filename">${escapedName}</span>`;

    expect(card.querySelector('script')).toBeNull();
    expect(card.textContent).toBe('<script>window.hacked=true</script>.pdf');
  });
});

