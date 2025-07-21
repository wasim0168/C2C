document.addEventListener('DOMContentLoaded', function() {
  // Validate price input
  document.getElementById('price').addEventListener('input', function(e) {
    if (this.value < 0) {
      this.value = 0;
    }
  });

  // Validate image file
  document.getElementById('image').addEventListener('change', function(e) {
    const file = this.files[0];
    if (file) {
      const validTypes = ['image/jpeg', 'image/png', 'image/jpg'];
      const maxSize = 5 * 1024 * 1024; // 5MB
      
      if (!validTypes.includes(file.type)) {
        this.setCustomValidity('Only JPEG, JPG, or PNG images are allowed');
        this.value = '';
      } else if (file.size > maxSize) {
        this.setCustomValidity('Image must be less than 5MB');
        this.value = '';
      } else {
        this.setCustomValidity('');
      }
    }
  });
});