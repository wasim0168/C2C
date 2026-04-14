// public/js/plan.js
document.addEventListener('DOMContentLoaded', function() {
  const planForms = document.querySelectorAll('.plan-form');
  
  planForms.forEach(form => {
    form.addEventListener('submit', async function(e) {
      e.preventDefault();
      
      const formData = new FormData(this);
      const planId = formData.get('plan_id');
      
      // Get the submit button
      const submitBtn = this.querySelector('button[type="submit"]');
      const originalText = submitBtn.innerHTML;
      
      try {
        // Show loading state
        submitBtn.disabled = true;
        submitBtn.innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> Processing...';
        
        // First validate if plan change is allowed
        const validationResponse = await fetch('/plans/validate-change', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({ plan_id: planId })
        });
        
        if (!validationResponse.ok) {
          const errorData = await validationResponse.json();
          throw new Error(errorData.message || 'Plan validation failed');
        }
        
        const validationResult = await validationResponse.json();
        
        if (!validationResult.valid) {
          throw new Error(validationResult.message || 'Cannot change to this plan');
        }
        
        // If validation passes, directly update the plan (NO PAYMENT)
        const updateResponse = await fetch('/plans/update', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({ plan_id: planId })
        });
        
        const updateResult = await updateResponse.json();
        
        if (!updateResult.success) {
          throw new Error(updateResult.message || 'Failed to update plan');
        }
        
        // Show success message and reload
        window.location.href = '/profile?plan=changed';
        
      } catch (error) {
        console.error('Error:', error);
        alert(error.message || 'Plan change failed');
      } finally {
        // Reset button state
        if (submitBtn) {
          submitBtn.disabled = false;
          submitBtn.innerHTML = originalText;
        }
      }
    });
  });
});