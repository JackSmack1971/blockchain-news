import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import { ThemeProvider } from 'next-themes';
import { Toaster } from 'sonner';
import './index.css';

// Layout Components
import Header from './components/layout/Header';
import Footer from './components/layout/Footer';

// Pages
import HomePage from './components/pages/HomePage';
import MarketDataPage from './components/pages/MarketDataPage';
import CategoryPage from './components/pages/CategoryPage';
import ArticlePage from './components/pages/ArticlePage';
import AuthPage from './components/pages/AuthPage';
import ProfilePage from './components/pages/ProfilePage';
import AboutPage from './components/pages/AboutPage';

// Context Providers
import { AuthProvider } from './contexts/AuthContext';
import { DataProvider } from './contexts/DataContext';

function App() {
  return (
    <ThemeProvider attribute="class" defaultTheme="light" enableSystem>
      <AuthProvider>
        <DataProvider>
          <Router>
            <div className="min-h-screen bg-background text-foreground">
              <Header />
              <main className="flex-1">
                <Routes>
                  <Route path="/" element={<HomePage />} />
                  <Route path="/market-data" element={<MarketDataPage />} />
                  <Route path="/category/:categorySlug" element={<CategoryPage />} />
                  <Route path="/article/:articleSlug" element={<ArticlePage />} />
                  <Route path="/auth" element={<AuthPage />} />
                  <Route path="/profile" element={<ProfilePage />} />
                  <Route path="/about" element={<AboutPage />} />
                </Routes>
              </main>
              <Footer />
            </div>
            <Toaster position="top-right" />
          </Router>
        </DataProvider>
      </AuthProvider>
    </ThemeProvider>
  );
}

export default App;
