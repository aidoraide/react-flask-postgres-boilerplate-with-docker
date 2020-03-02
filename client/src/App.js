import React, { useState } from 'react';
import './App.css';
import { isAuthenticated, APIError } from './api/API';
import { me } from './api/user';
import { signup, login, logoutEverywhere } from './api/auth';

function App() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [isLoggedIn, setIsLoggedIn] = useState(isAuthenticated());
  const [meUser, setMeUser] = useState({});

  return (
    <div>
      <p>Email</p>
      <input onChange={event => setEmail(event.target.value)} />
      <p>Password</p>
      <input type="password" onChange={event => setPassword(event.target.value)} />
      <button onClick={async () => {
        try {
          await signup(email, password);
        } catch (error) {
          return;
        }

        setIsLoggedIn(isAuthenticated());
        setMeUser(await me());
      }}>
        Sign Up
      </button>
      <button onClick={async () => {
        try {
          await login(email, password);
        } catch (error) {
          return;
        }

        setIsLoggedIn(isAuthenticated());
        setMeUser(await me());
      }}>
        Login
      </button>
      <button onClick={async () => {
        try {
          await logoutEverywhere();
        } catch (error) {
          return;
        }

        setIsLoggedIn(isAuthenticated());
        setMeUser({});
      }}>
        Logout
      </button>
      <p>{isLoggedIn ? 'LOGGED IN' : 'NOT LOGGED IN'}</p>
      <p>My ID: {meUser.id}</p>
      <p>My email: {meUser.email}</p>
    </div>
  );
}

export default App;
