document.addEventListener('DOMContentLoaded', function() {
  const planForms = document.querySelectorAll('#planForm');
  
  planForms.forEach(form => {
    form.addEventListener('submit', async function(e) {
      e.preventDefault(); // Prevent default form submission
      
      const formData = new FormData(form);
      const planId = formData.get('plan_id');
      
      try {
        const response = await fetch('/plans/select', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({ plan_id: planId })
        });
        
        if (response.ok) {
          const result = await response.json();
          if (result.redirect) {
            window.location.href = result.redirect;
          }
        } else {
          alert('Error selecting plan');
        }
      } catch (error) {
        console.error('Error:', error);
        alert('An error occurred');
      }
    });
  });
});