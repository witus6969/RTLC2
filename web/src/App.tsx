import { useEffect } from 'react';
import { Routes, Route, Navigate } from 'react-router-dom';
import { useAuthStore } from './store/authStore';
import LoginPage from './pages/LoginPage';
import MainPage from './pages/MainPage';

export default function App() {
  const { isAuthenticated, restoreSession } = useAuthStore();

  useEffect(() => {
    restoreSession();
  }, []);

  return (
    <Routes>
      <Route path="/login" element={isAuthenticated ? <Navigate to="/" /> : <LoginPage />} />
      <Route path="/*" element={isAuthenticated ? <MainPage /> : <Navigate to="/login" />} />
    </Routes>
  );
}
