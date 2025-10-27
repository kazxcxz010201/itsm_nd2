

def admin():
    if current_user.username.lower() != 'admin':
        flash('Access denied! Admin privileges required.', 'danger')
        return redirect(url_for('dashboard'))
    
    conn = get_db()
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    cursor.execute("SELECT id, username, email FROM users ORDER BY id")
    users = cursor.fetchall()
    conn.close()
    
    return render_template('admin.html', users=users)


def admin_edit_user(user_id):
    if current_user.username.lower() != 'admin':
        flash('Access denied! Admin privileges required.', 'danger')
        return redirect(url_for('dashboard'))
    
    conn = get_db()
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    
    if request.method == 'POST':
        new_username = request.form.get('username')
        new_email = request.form.get('email')
        new_password = request.form.get('password')
        
        if not new_username or not new_email:
            flash('Username and email are required!', 'danger')
            return redirect(url_for('admin_edit_user', user_id=user_id))
        
        cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
        target_user = cursor.fetchone()
        
        if not target_user:
            flash('User not found!', 'danger')
            conn.close()
            return redirect(url_for('admin'))
        
        if target_user['username'].lower() == 'admin' and new_username != 'admin':
            flash('Admin username cannot be changed!', 'danger')
            conn.close()
            return redirect(url_for('admin_edit_user', user_id=user_id))
        
        cursor.execute("SELECT * FROM users WHERE username = %s AND id != %s", (new_username, user_id))
        if cursor.fetchone():
            flash('Username already exists!', 'danger')
            conn.close()
            return redirect(url_for('admin_edit_user', user_id=user_id))
        
        cursor.execute("SELECT * FROM users WHERE email = %s AND id != %s", (new_email, user_id))
        if cursor.fetchone():
            flash('Email already registered!', 'danger')
            conn.close()
            return redirect(url_for('admin_edit_user', user_id=user_id))
        
        if new_password:
            password_hash = generate_password_hash(new_password)
            cursor.execute("UPDATE users SET username = %s, email = %s, password_hash = %s WHERE id = %s",
                          (new_username, new_email, password_hash, user_id))
        else:
            cursor.execute("UPDATE users SET username = %s, email = %s WHERE id = %s",
                          (new_username, new_email, user_id))
        
        conn.commit()
        conn.close()
        
        flash('User updated successfully!', 'success')
        return redirect(url_for('admin'))
    
    cursor.execute("SELECT id, username, email FROM users WHERE id = %s", (user_id,))
    user = cursor.fetchone()
    conn.close()
    
    if not user:
        flash('User not found!', 'danger')
        return redirect(url_for('admin'))
    
    return render_template('admin_edit_user.html', user=user)