// Cart functionality
const cartItems = [];
const cartTotal = document.getElementById("cart-total");
const cartItemsList = document.getElementById("cart-items");

// Example product data
const products = [
  { id: 1, name: "Necklace", price: 200 },
  { id: 2, name: "Ring", price: 45 },
  // add other products
];

// Add item to cart
function addToCart(productId) {
  const product = products.find(p => p.id === productId);
  cartItems.push(product);
  updateCart();
}

// Update cart display
function updateCart() {
  cartItemsList.innerHTML = "";
  let total = 0;

  cartItems.forEach((item) => {
    const li = document.createElement("li");
    li.textContent = `${item.name} - $${item.price}`;
    cartItemsList.appendChild(li);
    total += item.price;
  });

  cartTotal.textContent = total.toFixed(2);
}

// Example: Add a product to cart by ID (this should be called when clicking an "Add to Cart" button)
addToCart(1);
