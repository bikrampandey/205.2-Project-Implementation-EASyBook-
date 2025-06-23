from app import app, db, Book, Category
with app.app_context():
    books = Book.query.all()
    for book in books:
        print(f"Book: {book.book_name}, ID: {book.book_id}, Image: {book.image_path}, Category ID: {book.category_id}")
    categories = Category.query.all()
    for category in categories:
        print(f"Category: {category.name}, ID: {category.category_id}")