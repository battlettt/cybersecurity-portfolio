import { useEffect, useState } from 'react';
import './App.css';

const API = 'http://localhost:4000';

export default function App() {
  const [user, setUser] = useState(() => {
    const saved = localStorage.getItem('user');
    return saved ? JSON.parse(saved) : null;
  });
  const [loginForm, setLoginForm] = useState({ username: '', password: '' });
  const [loginError, setLoginError] = useState('');
  const [reviews, setReviews] = useState([]);
  const [search, setSearch] = useState('');
  const [newReview, setNewReview] = useState({ movie_title: '', review_text: '' });
  const [adminUsers, setAdminUsers] = useState(null);

  const loadReviews = async (q = '') => {
    const url = q ? `${API}/api/reviews/search?q=${q}` : `${API}/api/reviews`;
    const res = await fetch(url);
    const data = await res.json();
    setReviews(Array.isArray(data) ? data : []);
  };

  useEffect(() => { loadReviews(); }, []);

  const login = async (e) => {
    e.preventDefault();
    setLoginError('');
    const res = await fetch(`${API}/api/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(loginForm),
    });
    const data = await res.json();
    if (data.success) {
      setUser(data.user);
      localStorage.setItem('user', JSON.stringify(data.user));
    } else {
      setLoginError(data.message || data.error || 'Login failed');
    }
  };

  const logout = () => {
    setUser(null);
    localStorage.removeItem('user');
    setAdminUsers(null);
  };

  const postReview = async (e) => {
    e.preventDefault();
    await fetch(`${API}/api/reviews`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      // VULNERABLE: author_id is taken from client state, not a verified session.
      body: JSON.stringify({ ...newReview, author_id: user?.id || 1 }),
    });
    setNewReview({ movie_title: '', review_text: '' });
    loadReviews(search);
  };

  const deleteReview = async (id) => {
    // VULNERABLE: no ownership/role check server-side — any client can delete any review.
    await fetch(`${API}/api/reviews/${id}`, {
      method: 'DELETE',
      headers: { 'x-user-id': String(user?.id || 0) },
    });
    loadReviews(search);
  };

  const loadAdminUsers = async () => {
    // VULNERABLE: role is read straight from localStorage and sent as a header —
    // trivially edited in devtools by any logged-in-or-not user.
    const res = await fetch(`${API}/api/admin/users`, {
      headers: { 'x-role': user?.role || 'user' },
    });
    if (res.status === 403) {
      setAdminUsers({ error: 'Forbidden (403) — try editing x-role in devtools/localStorage' });
      return;
    }
    setAdminUsers(await res.json());
  };

  return (
    <div className="app">
      <header>
        <h1>MovieReviews <span className="badge-vuln">VULNERABLE BUILD</span></h1>
        {user ? (
          <div className="userbar">
            Logged in as <strong>{user.username}</strong> ({user.role}) <button onClick={logout}>Log out</button>
            {user.role === 'admin' && <button onClick={loadAdminUsers}>Load /api/admin/users</button>}
          </div>
        ) : (
          <form onSubmit={login} className="login-form">
            <input placeholder="username" value={loginForm.username}
              onChange={e => setLoginForm({ ...loginForm, username: e.target.value })} />
            <input placeholder="password" type="password" value={loginForm.password}
              onChange={e => setLoginForm({ ...loginForm, password: e.target.value })} />
            <button type="submit">Log in</button>
            {loginError && <span className="error">{loginError}</span>}
          </form>
        )}
      </header>

      {adminUsers && (
        <pre className="admin-dump">{JSON.stringify(adminUsers, null, 2)}</pre>
      )}

      <section className="search">
        <input placeholder="Search movie title..." value={search}
          onChange={e => setSearch(e.target.value)} />
        <button onClick={() => loadReviews(search)}>Search</button>
      </section>

      {user && (
        <form onSubmit={postReview} className="review-form">
          <input placeholder="Movie title" value={newReview.movie_title}
            onChange={e => setNewReview({ ...newReview, movie_title: e.target.value })} />
          <textarea placeholder="Your review (HTML allowed!)" value={newReview.review_text}
            onChange={e => setNewReview({ ...newReview, review_text: e.target.value })} />
          <button type="submit">Post review</button>
        </form>
      )}

      <ul className="reviews">
        {reviews.map(r => (
          <li key={r.id}>
            <h3>{r.movie_title}</h3>
            {/* VULNERABLE: renders stored review_text as raw HTML -> stored XSS */}
            <div dangerouslySetInnerHTML={{ __html: r.review_text }} />
            {user && <button onClick={() => deleteReview(r.id)}>Delete</button>}
          </li>
        ))}
      </ul>
    </div>
  );
}
