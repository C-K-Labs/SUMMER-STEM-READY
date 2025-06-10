from flask import Flask, request, jsonify, send_from_directory # import send_from_directory
from flask_cors import CORS
import json
import os
from datetime import datetime

# Set 'pocWebsite' folder as static file folder
app = Flask(__name__, static_folder='pocWebsite')
CORS(app)  # Allow browser access

# JSON file path
USERS_FILE = 'users.json'

def load_users():
    """Load user data from JSON file"""
    if not os.path.exists(USERS_FILE):
        return {"users": {}}
    
    try:
        with open(USERS_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    except:
        return {"users": {}}

def save_users(data):
    """Save user data to JSON file"""
    try:
        with open(USERS_FILE, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        return True
    except:
        return False

@app.route('/')
def home():
    """Server status check"""
    return jsonify({
        "status": "running",
        "message": "ScreenLocker PoC Server",
        "timestamp": datetime.now().isoformat()
    })

@app.route('/register', methods=['POST'])
def register_user():
    """Register new user (only if not exists)"""
    try:
        data = request.get_json()
        user_id = data.get('user_id')
        mac_address = data.get('mac_address', '')
        
        if not user_id:
            return jsonify({"error": "user_id is required"}), 400
        
        users_data = load_users()
        
        # Check if user already exists
        if user_id in users_data['users']:
            existing_user = users_data['users'][user_id]
            # Update only last_seen, preserve existing status
            existing_user['last_seen'] = datetime.now().isoformat()
            save_users(users_data)
            
            print(f"[REGISTER] Existing user: {user_id} (Status preserved: {existing_user['status']})")
            return jsonify({
                "message": "User already exists, status preserved",
                "user_id": user_id,
                "status": existing_user['status']
            })
        
        # Register new user with default locked status
        users_data['users'][user_id] = {
            "status": "locked",  # Default for new users only
            "mac_address": mac_address,
            "registered_at": datetime.now().isoformat(),
            "last_seen": datetime.now().isoformat(),
            "admin_fixed": False  # Track if admin has manually fixed status
        }
        
        if save_users(users_data):
            print(f"[REGISTER] New user: {user_id} (MAC: {mac_address})")
            return jsonify({
                "message": "User registered successfully",
                "user_id": user_id,
                "status": "locked"
            })
        else:
            return jsonify({"error": "Failed to save user data"}), 500
            
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/status/<user_id>', methods=['GET'])
def get_status(user_id):
    """Get user status"""
    try:
        users_data = load_users()
        
        if user_id not in users_data['users']:
            return jsonify({"error": "User not found"}), 404
        
        user = users_data['users'][user_id]
        
        # Update last seen time only (don't change status)
        user['last_seen'] = datetime.now().isoformat()
        save_users(users_data)
        
        print(f"[STATUS] {user_id}: {user['status']}")
        
        return jsonify({
            "user_id": user_id,
            "status": user['status'],
            "last_seen": user['last_seen']
        })
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/status/<user_id>', methods=['PUT'])
def update_status(user_id):
    """Update user status (admin only - locks the status)"""
    try:
        data = request.get_json()
        new_status = data.get('status')
        
        if new_status not in ['locked', 'unlocked']:
            return jsonify({"error": "Invalid status. Use 'locked' or 'unlocked'"}), 400
        
        users_data = load_users()
        
        if user_id not in users_data['users']:
            return jsonify({"error": "User not found"}), 404
        
        old_status = users_data['users'][user_id]['status']
        users_data['users'][user_id]['status'] = new_status
        users_data['users'][user_id]['updated_at'] = datetime.now().isoformat()
        users_data['users'][user_id]['admin_fixed'] = True  # Mark as admin fixed
        
        if save_users(users_data):
            print(f"[ADMIN_STATUS_UPDATE] {user_id}: {old_status} → {new_status} (STATUS FIXED)")
            return jsonify({
                "message": "Status updated and fixed by admin",
                "user_id": user_id,
                "old_status": old_status,
                "new_status": new_status,
                "admin_fixed": True
            })
        else:
            return jsonify({"error": "Failed to save user data"}), 500
            
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/users', methods=['GET'])
def list_users():
    """List all users (for admin)"""
    try:
        users_data = load_users()
        return jsonify(users_data)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/users/<user_id>', methods=['DELETE'])
def delete_user(user_id):
    """Delete user (admin only)"""
    try:
        users_data = load_users()
        
        if user_id not in users_data['users']:
            return jsonify({"error": "User not found"}), 404
        
        del users_data['users'][user_id]
        
        if save_users(users_data):
            print(f"[DELETE] User deleted: {user_id}")
            return jsonify({
                "message": "User deleted successfully",
                "user_id": user_id
            })
        else:
            return jsonify({"error": "Failed to save user data"}), 500
            
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/admin')
def admin_panel():
    """Admin panel for managing users"""
    return '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>ScreenLocker Admin Panel</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
            .container { max-width: 1000px; margin: 0 auto; }
            h1 { color: #333; text-align: center; }
            .user-card { border: 1px solid #ccc; margin: 10px 0; padding: 15px; border-radius: 5px; background: white; }
            .locked { border-left: 5px solid #f44336; }
            .unlocked { border-left: 5px solid #4CAF50; }
            .admin-fixed { border: 2px solid #FF9800; background-color: #FFF3E0; }
            button { padding: 8px 16px; margin: 5px; cursor: pointer; border: none; border-radius: 3px; }
            .unlock-btn { background-color: #4CAF50; color: white; }
            .lock-btn { background-color: #f44336; color: white; }
            .delete-btn { background-color: #FF5722; color: white; }
            .status-badge { padding: 4px 8px; border-radius: 12px; color: white; font-size: 12px; margin-left: 10px; }
            .status-locked { background-color: #f44336; }
            .status-unlocked { background-color: #4CAF50; }
            .admin-badge { background-color: #FF9800; }
            .refresh-btn { background-color: #2196F3; color: white; padding: 10px 20px; }
            .warning { color: #FF5722; font-weight: bold; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🔐 ScreenLocker Admin Panel</h1>
            <button class="refresh-btn" onclick="loadUsers()">🔄 Refresh</button>
            <div id="users-list">Loading users...</div>
        </div>
        
        <script>
            async function loadUsers() {
                try {
                    const response = await fetch('/users');
                    const data = await response.json();
                    const usersList = document.getElementById('users-list');
                    
                    if (Object.keys(data.users).length === 0) {
                        usersList.innerHTML = '<div class="user-card"><p>No users registered yet.</p></div>';
                        return;
                    }
                    
                    let html = '';
                    for (const [userId, userInfo] of Object.entries(data.users)) {
                        const statusClass = userInfo.status === 'locked' ? 'locked' : 'unlocked';
                        const statusIcon = userInfo.status === 'locked' ? '🔒' : '🔓';
                        const badgeClass = userInfo.status === 'locked' ? 'status-locked' : 'status-unlocked';
                        const adminFixed = userInfo.admin_fixed || false;
                        const adminClass = adminFixed ? 'admin-fixed' : '';
                        
                        html += `
                            <div class="user-card ${statusClass} ${adminClass}">
                                <h3>${statusIcon} User: ${userId} 
                                    <span class="status-badge ${badgeClass}">${userInfo.status.toUpperCase()}</span>
                                    ${adminFixed ? '<span class="status-badge admin-badge">STATUS FIXED</span>' : ''}
                                </h3>
                                <p><strong>MAC Address:</strong> ${userInfo.mac_address}</p>
                                <p><strong>Registered:</strong> ${new Date(userInfo.registered_at).toLocaleString()}</p>
                                <p><strong>Last Seen:</strong> ${new Date(userInfo.last_seen).toLocaleString()}</p>
                                ${adminFixed ? '<p class="warning">⚠️ Status is fixed by administrator</p>' : ''}
                                
                                <div>
                                    ${userInfo.status === 'locked' ? 
                                        `<button class="unlock-btn" onclick="changeStatus('${userId}', 'unlocked')">🔓 UNLOCK USER</button>` :
                                        `<button class="lock-btn" onclick="changeStatus('${userId}', 'locked')">🔒 LOCK USER</button>`
                                    }
                                    <button class="delete-btn" onclick="deleteUser('${userId}')">🗑️ DELETE USER</button>
                                </div>
                            </div>
                        `;
                    }
                    
                    usersList.innerHTML = html;
                } catch (error) {
                    document.getElementById('users-list').innerHTML = '<div class="user-card"><p>Error loading users: ' + error.message + '</p></div>';
                }
            }
            
            async function changeStatus(userId, newStatus) {
                try {
                    const response = await fetch(`/status/${userId}`, {
                        method: 'PUT',
                        headers: {
                            'Content-Type': 'application/json'
                        },
                        body: JSON.stringify({
                            status: newStatus
                        })
                    });
                    
                    const result = await response.json();
                    
                    if (response.ok) {
                        alert(`✅ Status changed: ${userId} is now ${newStatus.toUpperCase()} and FIXED by admin`);
                        loadUsers(); // Reload the user list
                    } else {
                        alert('❌ Error: ' + result.error);
                    }
                } catch (error) {
                    alert('❌ Network error: ' + error.message);
                }
            }
            
            async function deleteUser(userId) {
                if (!confirm(`⚠️ Are you sure you want to delete user "${userId}"?\\n\\nThis action cannot be undone!`)) {
                    return;
                }
                
                try {
                    const response = await fetch(`/users/${userId}`, {
                        method: 'DELETE'
                    });
                    
                    const result = await response.json();
                    
                    if (response.ok) {
                        alert(`✅ User "${userId}" has been deleted successfully`);
                        loadUsers(); // Reload the user list
                    } else {
                        alert('❌ Error: ' + result.error);
                    }
                } catch (error) {
                    alert('❌ Network error: ' + error.message);
                }
            }
            
            // Load users when page loads
            loadUsers();
            
            // Auto-refresh every 15 seconds
            setInterval(loadUsers, 15000);
        </script>
    </body>
    </html>
    '''

@app.route('/website')
def serve_poc_website():
    # app.static_folder (i.e., 'pocWebsite') to find and serve 'poc_website.html' file
    return send_from_directory(app.static_folder, 'poc_website.html')

@app.route('/download/<path:filename>')
def download_file(filename):
    try:
        return send_from_directory(app.static_folder, filename, as_attachment=True)
    except FileNotFoundError:
        return "Error: File not found on server.", 404

if __name__ == '__main__':
    print("🚀 ScreenLocker PoC Server Starting...")
    print("📡 Server URL: http://localhost:5000")
    print("📊 Raw Users API: http://localhost:5000/users")
    print("🎛️ Admin Panel: http://localhost:5000/admin")
    app.run(host='0.0.0.0', port=5000, debug=True)