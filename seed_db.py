from app import init_db, seed

if __name__ == "__main__":
    init_db()
    seed()
    print("Database seeded with alice, bob, admin.")