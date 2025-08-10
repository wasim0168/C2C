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
        
        // First validate the plan change
        const validationResponse = await fetch('/plans/validate-change', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
           
          },
          body: JSON.stringify({ plan_id: planId })
        });
        
        if (!validationResponse.ok) {
          const errorData = await validationResponse.json();
          throw new Error(errorData.error || 'Plan validation failed');
        }
        
        const validationResult = await validationResponse.json();
        
        if (!validationResult.valid) {
          throw new Error(validationResult.message || 'Cannot upgrade to this plan');
        }
        
        // Then create the Razorpay order
        const orderResponse = await fetch('/plans/create-order', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          
          },
          body: JSON.stringify({ plan_id: planId })
        });
        
        if (!orderResponse.ok) {
          const errorData = await orderResponse.json();
          throw new Error(errorData.error || 'Failed to create order');
        }
        
        const order = await orderResponse.json();
        
        // Check if Razorpay is available
        if (typeof Razorpay === 'undefined') {
          throw new Error('Payment system is currently unavailable. Please try again later.');
        }
        
        // Initialize Razorpay with your key from environment variables
        const razorpayKey = document.querySelector('meta[name="razorpay-key"]').content;
        
        const options = {
          key: razorpayKey,
          amount: order.amount,
          currency: 'INR',
          name: "Your App Name",
          description: `Upgrade to Plan ${planId}`,
          order_id: order.id,
          handler: async function(response) {
            try {
              const verification = await fetch('/plans/verify-payment', {
                method: 'POST',
                headers: {
                  'Content-Type': 'application/json',
                  
                },
                body: JSON.stringify({
                  razorpay_payment_id: response.razorpay_payment_id,
                  razorpay_order_id: response.razorpay_order_id,
                  razorpay_signature: response.razorpay_signature,
                  plan_id: planId
                })
              });
              
              const result = await verification.json();
              
              if (!result.success) {
                throw new Error(result.message || 'Payment verification failed');
              }
              
              // Show success message and reload
              window.location.href = '/profile?payment=success';
            } catch (error) {
              console.error('Verification error:', error);
              alert('Payment verification failed: ' + error.message);
            }
          },
          prefill: {
            name: '<%= user.name %>',
            email: '<%= user.email %>',
            contact: '<%= user.phone || "" %>'
          },
          theme: {
            color: '#3399cc'
          }
        };
        
        const rzp = new Razorpay(options);
        
        rzp.on('payment.failed', function(response) {
          console.error('Payment failed:', response.error);
          alert('Payment failed: ' + response.error.description);
        });
        
        rzp.open();
        
      } catch (error) {
        console.error('Error:', error);
        alert(error.message || 'Plan selection failed');
      } finally {
        // Reset button state
        submitBtn.disabled = false;
        submitBtn.innerHTML = originalText;
      }
    });
  });
});