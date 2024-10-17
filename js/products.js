document.addEventListener('DOMContentLoaded', function () {
    const products = [
      {
        id: 1,
        name: "Necklace",
        price: 200,
        imageUrl: "images/p1.png", 
        new: true
      },
      {
        id: 2,
        name: "Necklace",
        price: 300,
        imageUrl: "images/p2.png",
        new: true
      },
      {
        id: 3,
        name: "Necklace",
        price: 110,
        imageUrl: "images/p3.png",
        new: true
      },
      {
        id: 4,
        name: "Ring",
        price: 45,
        imageUrl: "images/p4.png",
        new: true
      },
      {
        id: 5,
        name: "Ring",
        price: 95,
        imageUrl: "images/p5.png",
        new: true
      },
      {
        id: 6,
        name: "Earrings",
        price: 70,
        imageUrl: "images/p6.png",
        new: true
      },
      {
        id: 7,
        name: "Earrings",
        price: 400,
        imageUrl: "images/p7.png",
        new: true
      },
      {
        id: 8,
        name: "Necklace",
        price: 450,
        imageUrl: "images/p8.png",
        new: true
      }
    ];
    
    // Dynamically generate the product listing
    const productContainer = document.getElementById('product-list');
    
    // Build the entire HTML first
    let productCards = '';
    
    products.forEach(product => {
      productCards += `
        <div class="product-card">
          <img src="${product.imageUrl}" alt="${product.name}">
          <h3>${product.name}</h3>
          <p>Price $${product.price}</p>
          <button class="add-to-cart" data-id="${product.id}">Add to Cart</button>
        </div>
      `;
    });
  
    // Append the generated HTML to the container once
    productContainer.innerHTML = productCards;
  });
  