import os
from pymongo import MongoClient as PyMongoClient
from pymongo.errors import ConnectionFailure
from datetime import datetime
from bson.objectid import ObjectId

class MongoClient:
    """MongoDB client for storing and retrieving scan results"""
    
    def __init__(self):
        self.connection_string = os.getenv("MONGODB_URI", "mongodb://localhost:27017")
        try:
            self.client = PyMongoClient(self.connection_string, serverSelectionTimeoutMS=5000)
            # Verify connection
            self.client.admin.command('ping')
            self.db = self.client.get_database("phishing_detection")
            self._ensure_collections()
            print("[v0] Connected to MongoDB")
        except ConnectionFailure:
            print(f"[v0] Warning: Could not connect to MongoDB at {self.connection_string}")
            self.client = None
            self.db = None
    
    def _ensure_collections(self):
        """Ensure required collections exist"""
        if self.db is not None:
            # Create scans collection with indexes
            if "scans" not in self.db.list_collection_names():
                self.db.create_collection("scans")
            
            # Create indexes for better query performance
            self.db.scans.create_index("timestamp")
            self.db.scans.create_index("type")
            self.db.scans.create_index([("timestamp", -1)])  # Descending for recent first
    
    def save_scan(self, scan_record: dict) -> str:
        """Save a scan record to MongoDB"""
        if self.db is None:
            print("[v0] MongoDB not connected, skipping save")
            return None
        
        try:
            result = self.db.scans.insert_one(scan_record)
            return str(result.inserted_id)
        except Exception as e:
            print(f"[v0] Error saving scan: {str(e)}")
            return None
    
    def get_scan(self, scan_id: str) -> dict:
        """Get a specific scan by ID"""
        if self.db is None:
            return None
        
        try:
            return self.db.scans.find_one({"_id": ObjectId(scan_id)})
        except Exception as e:
            print(f"[v0] Error retrieving scan: {str(e)}")
            return None
    
    def get_scans(self, limit: int = 50) -> list:
        """Get recent scans"""
        if self.db is None:
            return []
        
        try:
            scans = list(self.db.scans.find().sort("timestamp", -1).limit(limit))
            # Convert ObjectId to string for JSON serialization
            for scan in scans:
                scan["_id"] = str(scan["_id"])
                if isinstance(scan.get("timestamp"), datetime):
                    scan["timestamp"] = scan["timestamp"].isoformat()
            return scans
        except Exception as e:
            print(f"[v0] Error retrieving scans: {str(e)}")
            return []
    
    def delete_scan(self, scan_id: str) -> bool:
        """Delete a scan record"""
        if self.db is None:
            return False
        
        try:
            result = self.db.scans.delete_one({"_id": ObjectId(scan_id)})
            return result.deleted_count > 0
        except Exception as e:
            print(f"[v0] Error deleting scan: {str(e)}")
            return False
    
    def get_stats(self) -> dict:
        """Get scan statistics"""
        if self.db is None:
            return {}
        
        try:
            total_scans = self.db.scans.count_documents({})
            by_type = {}
            
            for scan_type in ["url", "message", "voice"]:
                count = self.db.scans.count_documents({"type": scan_type})
                by_type[scan_type] = count
            
            return {
                "total_scans": total_scans,
                "by_type": by_type
            }
        except Exception as e:
            print(f"[v0] Error getting stats: {str(e)}")
            return {}
    # Inside backend/database/mongo_client.py
def get_recent_scans(self, limit=10):
    try:
        # 1. Convert the cursor to a list
        scans = list(self.db.scans.find().sort("timestamp", -1).limit(limit))
        
        # 2. Convert MongoDB ObjectId to a string so FastAPI can send it
        for scan in scans:
            scan["_id"] = str(scan["_id"])
            
        return scans
    except Exception as e:
        print(f"Database Error: {e}")
        return []
