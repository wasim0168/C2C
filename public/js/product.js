// Validate product links on client side
document.addEventListener('DOMContentLoaded', function() {
  // Fix malformed product links
  document.querySelectorAll('a[href*="/products/"]').forEach(link => {
    const match = link.getAttribute('href').match(/\/products\/(\d+)/);
    if (!match) {
      console.warn('Invalid product link:', link.href);
      link.addEventListener('click', function(e) {
        e.preventDefault();
        alert('Invalid product link. Please report this issue.');
      });
    }
  });

  // Handle form submissions with product IDs
  document.querySelectorAll('form[action*="/products/"]').forEach(form => {
    form.addEventListener('submit', function(e) {
      const action = this.getAttribute('action');
      const productId = action.match(/\/products\/(\d+)/)?.[1];
      
      if (!productId || isNaN(productId)) {
        e.preventDefault();
        alert('Invalid product reference. Please try again.');
        return false;
      }
    });
  });
});