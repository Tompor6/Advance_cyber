import sqlite3

# Valid public URLs for book covers (using Amazon/Goodreads/Publisher sources or placeholders)
# These are standard book covers found online.
COVERS = {
    "Onyx Storm (The Empyrean, #3)": "https://images-na.ssl-images-amazon.com/images/S/compressed.photo.goodreads.com/books/1711636168i/209620531.jpg",
    "Sunrise on the Reaping": "https://images-na.ssl-images-amazon.com/images/S/compressed.photo.goodreads.com/books/1717676644i/213071373.jpg",
    "Great Big Beautiful Life": "https://images-na.ssl-images-amazon.com/images/S/compressed.photo.goodreads.com/books/1709230538i/200547074.jpg",
    "Atmosphere": "https://images-na.ssl-images-amazon.com/images/S/compressed.photo.goodreads.com/books/1702315729i/199320299.jpg",
    "The Crash": "https://images-na.ssl-images-amazon.com/images/S/compressed.photo.goodreads.com/books/1689602492i/123284042.jpg",
    "The Tenant": "https://images-na.ssl-images-amazon.com/images/S/compressed.photo.goodreads.com/books/1586360431i/50027878.jpg",
    "James": "https://images-na.ssl-images-amazon.com/images/S/compressed.photo.goodreads.com/books/1705348083i/195609460.jpg",
    "On Tyranny": "https://images-na.ssl-images-amazon.com/images/S/compressed.photo.goodreads.com/books/1487371900i/33917107.jpg",
    # Default for others
    "DEFAULT": "https://images.unsplash.com/photo-1543002588-bfa74002ed7e?q=80&w=2730&auto=format&fit=crop"
}

conn = sqlite3.connect('shop.db')
c = conn.cursor()

# Get all products
c.execute("SELECT id, name FROM products")
products = c.fetchall()

for pid, name in products:
    url = COVERS.get(name, COVERS["DEFAULT"])
    c.execute("UPDATE products SET image = ? WHERE id = ?", (url, pid))
    print(f"Updated {name} -> {url[:30]}...")

conn.commit()
conn.close()
print("Done updating covers.")
