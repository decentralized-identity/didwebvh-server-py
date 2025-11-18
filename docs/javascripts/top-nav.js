// Top Navigation Bar for Zensical
(function() {
  'use strict';
  
  function initTopNav() {
    // Check if already added
    if (document.querySelector('.webvh-top-nav')) {
      return;
    }
    
    // Create top navigation bar
    const topNav = document.createElement('nav');
    topNav.className = 'webvh-top-nav';
    topNav.innerHTML = `
      <div class="webvh-top-nav__inner">
        <a href="index.html" class="webvh-top-nav__link">Home</a>
        <a href="user-manual.html" class="webvh-top-nav__link">User Manual</a>
        <a href="api-endpoints.html" class="webvh-top-nav__link">API Reference</a>
        <a href="protocols.html" class="webvh-top-nav__link">Guides</a>
      </div>
    `;
    
    // Insert after header
    const header = document.querySelector('.md-header');
    if (header && header.parentNode) {
      header.parentNode.insertBefore(topNav, header.nextSibling);
      
      // Set active link based on current page
      const currentPath = window.location.pathname;
      const currentPage = currentPath.split('/').pop() || 'index.html';
      
      topNav.querySelectorAll('.webvh-top-nav__link').forEach(link => {
        const linkPage = link.getAttribute('href');
        if (currentPage === linkPage || 
            (currentPage.includes(linkPage.replace('.html', '')) && linkPage !== 'index.html')) {
          link.classList.add('webvh-top-nav__link--active');
        }
      });
    }
  }
  
  // Initialize when DOM is ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initTopNav);
  } else {
    initTopNav();
  }
  
  // Also try after a short delay in case Zensical loads content dynamically
  setTimeout(initTopNav, 100);
})();

