import { useEffect, useState } from 'react';
import './App.css';

const API = 'http://localhost:4001';

export default function App() {
  const [session, setSession] = useState(() => {
    const saved = localStorage.getItem('session');
    return saved ? JSON.parse(saved) : null; // { token, user }
  });
  const [loginForm, setLoginForm] = useState({ username: '', password: '' });
  const [loginError, setLoginError] = useState('');
  const [reviews, setReviews] = useState([]);
  const [search, setSearch] = useState('');
  const [newReview, setNewReview] = useState({ movie_title: '', review_text: '' });
  const [adminUsers, setAdminUsers] = useState(null);
  const [adminError, setAdminError] = useState('');

  const loadReviews = async (q = '') => {
    const url = q ? `${API}/api/reviews/search?q=${encodeURIComponent(q)}` : `${API}/api/reviews`;
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
      setSession(data);
      localStorage.setItem('session', JSON.stringify(data));
    } else {
      setLoginError(data.message || 'Login failed');
    }
  };

  const logout = () => {
    setSession(null);
    localStorage.removeItem('session');
    setAdminUsers(null);
    setAdminError('');
  };

  const authHeaders = () => ({
    'Content-Type': 'application/json',
    ...(session ? { Authorization: `Bearer ${session.token}` } : {}),
  });

  const postReview = async (e) => {
    e.preventDefault();
    // FIX: author_id is no longer sent by the client at all — the server
    // derives it from the verified JWT.
    await fetch(`${API}/api/reviews`, {
      method: 'POST',
      headers: authHeaders(),
      body: JSON.stringify(newReview),
    });
    setNewReview({ movie_title: '', review_text: '' });
    loadReviews(search);
  };

  const deleteReview = async (id) => {
    const res = await fetch(`${API}/api/reviews/${id}`, {
      method: 'DELETE',
      headers: authHeaders(),
    });
    if (res.status === 403) {
      alert('Forbidden — the server rejected this because you are not the author or an admin.');
      return;
    }
    loadReviews(search);
  };

  const loadAdminUsers = async () => {
    setAdminError('');
    const res = await fetch(`${API}/api/admin/users`, { headers: authHeaders() });
    if (res.status === 403) {
      setAdminError('403 Forbidden — server checked the role in the signed JWT, not a client header.');
      return;
    }
    setAdminUsers(await res.json());
  };

  return (
    <div className="app">
      <header>
        <h1>MovieReviews <span className="badge-secure">SECURE BUILD</span></h1>
        {session ? (
          <div className="userbar">
            Logged in as <strong>{session.user.username}</strong> ({session.user.role}) <button onClick={logout}>Log out</button>
            {session.user.role === 'admin' && <button onClick={loadAdminUsers}>Load /api/admin/users</button>}
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

      {adminError && <pre className="admin-dump error-dump">{adminError}</pre>}
      {adminUsers && <pre className="admin-dump">{JSON.stringify(adminUsers, null, 2)}</pre>}

      <section className="search">
        <input placeholder="Search movie title..." value={search}
          onChange={e => setSearch(e.target.value)} />
        <button onClick={() => loadReviews(search)}>Search</button>
      </section>

      {session && (
        <form onSubmit={postReview} className="review-form">
          <input placeholder="Movie title" value={newReview.movie_title}
            onChange={e => setNewReview({ ...newReview, movie_title: e.target.value })} />
          <textarea placeholder="Your review (HTML is stripped server-side)" value={newReview.review_text}
            onChange={e => setNewReview({ ...newReview, review_text: e.target.value })} />
          <button type="submit">Post review</button>
        </form>
      )}

      <ul className="reviews">
        {reviews.map(r => (
          <li key={r.id}>
            <h3>{r.movie_title}</h3>
            {/* FIX: rendered as plain text (React escapes by default) — never
                dangerouslySetInnerHTML — so injected markup can't execute. */}
            <p>{r.review_text}</p>
            {session && (session.user.id === r.author_id || session.user.role === 'admin') && (
              <button onClick={() => deleteReview(r.id)}>Delete</button>
            )}
          </li>
        ))}
      </ul>
    </div>
  );
}
