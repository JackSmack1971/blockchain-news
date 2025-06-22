import React, { useState } from 'react';
import {
  Search,
  Moon,
  Sun,
  Menu,
  X,
  ChevronDown,
  Filter,
  Grid,
  List,
  Bookmark,
  BookmarkCheck,
  TrendingUp,
  Calendar,
  Clock,
  ArrowLeft,
} from 'lucide-react';

// Types
export interface CryptoPrice {
  symbol: string;
  price: string;
  change: string;
  isPositive: boolean;
}

export interface Article {
  id: string;
  title: string;
  excerpt: string;
  category: string;
  author: string;
  publishedAt: string;
  readTime: string;
  image: string;
  trending?: boolean;
  featured?: boolean;
}

export interface CategoryHero {
  name: string;
  description: string;
  totalArticles: number;
  featured: number;
  trending: number;
  lastUpdated: string;
  gradient: string;
}

// Mock Data
const cryptoPrices: CryptoPrice[] = [
  { symbol: 'BTC', price: '$60,996', change: '+23.95%', isPositive: true },
  { symbol: 'ETH', price: '$4,405', change: '-18.47%', isPositive: false },
  { symbol: 'BNB', price: '$804.76', change: '+4.52%', isPositive: true },
  { symbol: 'SOL', price: '$180.74', change: '+4.96%', isPositive: true },
  { symbol: 'ADA', price: '$1.01', change: '-5.40%', isPositive: false },
  { symbol: 'LINK', price: '$34.16', change: '+14.60%', isPositive: true },
  { symbol: 'DOT', price: '$18.72', change: '-30.99%', isPositive: false },
  { symbol: 'MATIC', price: '$2.28', change: '-1.18%', isPositive: false },
];

const categories: Record<string, CategoryHero> = {
  'technology-updates': {
    name: 'Technology Updates',
    description:
      'Blockchain technology advancements, protocol upgrades, and technical innovations',
    totalArticles: 1,
    featured: 0,
    trending: 1,
    lastUpdated: '6/21/2025',
    gradient: 'bg-gradient-to-br from-blue-500 via-blue-600 to-purple-700',
  },
  nfts: {
    name: 'NFTs',
    description: 'Non-fungible tokens, digital art, and collectibles marketplace news',
    totalArticles: 1,
    featured: 0,
    trending: 0,
    lastUpdated: '6/21/2025',
    gradient: 'bg-gradient-to-br from-orange-500 via-orange-600 to-red-600',
  },
  'market-analysis': {
    name: 'Market Analysis',
    description:
      'In-depth analysis of cryptocurrency markets, price movements, and trading insights',
    totalArticles: 1,
    featured: 1,
    trending: 1,
    lastUpdated: '6/21/2025',
    gradient: 'bg-gradient-to-br from-green-500 via-green-600 to-emerald-700',
  },
};

const sampleArticles: Article[] = [
  {
    id: '1',
    title: "Ethereum's Shanghai Upgrade Unlocks $32 Billion in Staked ETH",
    excerpt:
      'The long-awaited Shanghai upgrade has finally arrived, enabling validators to withdraw their staked Ethereum for the first time since the beacon chain launched.',
    category: 'Technology Updates',
    author: 'Alex Chen',
    publishedAt: '2024-06-21',
    readTime: '5 min read',
    image: '/api/placeholder/400/250',
    trending: true,
  },
  {
    id: '2',
    title: 'NFT Market Shows Signs of Recovery with 45% Volume Increase',
    excerpt:
      'After months of declining activity, the NFT marketplace is experiencing renewed interest from both collectors and institutional investors.',
    category: 'NFTs',
    author: 'Sarah Mitchell',
    publishedAt: '2024-06-21',
    readTime: '3 min read',
    image: '/api/placeholder/400/250',
  },
  {
    id: '3',
    title: 'Bitcoin Reaches New All-Time High as Institutional Adoption Soars',
    excerpt:
      'Major corporations continue to add Bitcoin to their treasury reserves, driving prices to unprecedented levels amid growing mainstream acceptance.',
    category: 'Market Analysis',
    author: 'Michael Rodriguez',
    publishedAt: '2024-06-21',
    readTime: '7 min read',
    image: '/api/placeholder/400/250',
    featured: true,
    trending: true,
  },
];

const CryptoTicker: React.FC = () => (
  <div className="bg-black border-b border-gray-800 py-2 overflow-hidden">
    <div className="flex animate-scroll whitespace-nowrap">
      {[...cryptoPrices, ...cryptoPrices].map((crypto, index) => (
        <div key={index} className="inline-flex items-center mx-6 text-sm">
          <span className="text-white font-medium">{crypto.symbol}</span>
          <span className="text-white mx-2">{crypto.price}</span>
          <span className={crypto.isPositive ? 'text-green-400' : 'text-red-400'}>
            {crypto.change}
          </span>
        </div>
      ))}
    </div>
  </div>
);

const HeaderBar: React.FC<{ isDark: boolean; toggleTheme: () => void }> = ({
  isDark,
  toggleTheme,
}) => {
  const [isMenuOpen, setIsMenuOpen] = useState(false);
  return (
    <header className="bg-black border-b border-gray-800 sticky top-0 z-50">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">
          <div className="flex items-center">
            <div className="flex items-center space-x-2">
              <div className="w-8 h-8 bg-blue-600 rounded-lg flex items-center justify-center">
                <span className="text-white font-bold text-sm">BC</span>
              </div>
              <span className="text-white font-semibold text-lg">BlockchainNews</span>
            </div>
          </div>
          <nav className="hidden md:flex items-center space-x-8">
            <a href="#" className="text-white hover:text-blue-400 transition-colors">
              Home
            </a>
            <div className="relative group">
              <button className="text-white hover:text-blue-400 transition-colors flex items-center">
                Categories <ChevronDown className="ml-1 h-4 w-4" />
              </button>
            </div>
            <a href="#" className="text-white hover:text-blue-400 transition-colors">
              Market Data
            </a>
            <a href="#" className="text-white hover:text-blue-400 transition-colors">
              About
            </a>
          </nav>
          <div className="flex items-center space-x-4">
            <div className="relative hidden md:block">
              <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400 h-4 w-4" />
              <input
                type="text"
                placeholder="Search articles..."
                className="bg-gray-800 border border-gray-700 rounded-lg pl-10 pr-4 py-2 text-white placeholder-gray-400 focus:outline-none focus:border-blue-500 w-64"
              />
            </div>
            <button onClick={toggleTheme} className="p-2 text-gray-400 hover:text-white transition-colors">
              {isDark ? <Sun className="h-5 w-5" /> : <Moon className="h-5 w-5" />}
            </button>
            <button className="bg-white text-black px-4 py-2 rounded-lg text-sm font-medium hover:bg-gray-100 transition-colors">
              Sign In
            </button>
            <button onClick={() => setIsMenuOpen(!isMenuOpen)} className="md:hidden p-2 text-gray-400 hover:text-white">
              {isMenuOpen ? <X className="h-5 w-5" /> : <Menu className="h-5 w-5" />}
            </button>
          </div>
        </div>
      </div>
    </header>
  );
};

const CategoryHeroSection: React.FC<{ category: CategoryHero }> = ({ category }) => (
  <div className={`${category.gradient} rounded-xl p-8 mb-8`}>
    <div className="mb-4">
      <span className="bg-black/20 text-white px-3 py-1 rounded-full text-sm font-medium">Category</span>
    </div>
    <h1 className="text-4xl font-bold text-white mb-4">{category.name}</h1>
    <p className="text-white/90 text-lg mb-8 max-w-3xl">{category.description}</p>
    <div className="grid grid-cols-2 md:grid-cols-4 gap-8">
      <div>
        <div className="text-3xl font-bold text-white">{category.totalArticles}</div>
        <div className="text-white/80 text-sm">Total Articles</div>
      </div>
      <div>
        <div className="text-3xl font-bold text-white">{category.featured}</div>
        <div className="text-white/80 text-sm">Featured</div>
      </div>
      <div>
        <div className="text-3xl font-bold text-white">{category.trending}</div>
        <div className="text-white/80 text-sm">Trending</div>
      </div>
      <div>
        <div className="text-white/80 text-sm">Last Updated</div>
        <div className="text-white font-semibold">{category.lastUpdated}</div>
      </div>
    </div>
  </div>
);

const ArticleCard: React.FC<{
  article: Article;
  onBookmark: (id: string) => void;
  isBookmarked: boolean;
}> = ({ article, onBookmark, isBookmarked }) => {
  const getCategoryColor = (category: string) => {
    switch (category) {
      case 'Technology Updates':
        return 'bg-blue-100 text-blue-800';
      case 'NFTs':
        return 'bg-orange-100 text-orange-800';
      case 'Market Analysis':
        return 'bg-green-100 text-green-800';
      default:
        return 'bg-gray-100 text-gray-800';
    }
  };
  return (
    <div className="bg-white rounded-xl shadow-sm border border-gray-200 overflow-hidden hover:shadow-md transition-shadow">
      <div className="relative">
        <img src={article.image} alt={article.title} className="w-full h-48 object-cover" />
        <div className="absolute top-4 left-4">
          <span className={`px-3 py-1 rounded-full text-xs font-medium ${getCategoryColor(article.category)}`}>{article.category}</span>
        </div>
        {article.trending && (
          <div className="absolute top-4 right-4">
            <span className="bg-red-500 text-white px-2 py-1 rounded-full text-xs font-medium flex items-center">
              <TrendingUp className="h-3 w-3 mr-1" /> Trending
            </span>
          </div>
        )}
      </div>
      <div className="p-6">
        <h3 className="font-bold text-lg text-gray-900 mb-2 line-clamp-2">{article.title}</h3>
        <p className="text-gray-600 text-sm mb-4 line-clamp-3">{article.excerpt}</p>
        <div className="flex items-center justify-between text-sm text-gray-500">
          <div className="flex items-center space-x-4">
            <span>{article.author}</span>
            <div className="flex items-center">
              <Calendar className="h-4 w-4 mr-1" />
              {new Date(article.publishedAt).toLocaleDateString()}
            </div>
            <div className="flex items-center">
              <Clock className="h-4 w-4 mr-1" />
              {article.readTime}
            </div>
          </div>
          <button onClick={() => onBookmark(article.id)} className="p-2 hover:bg-gray-100 rounded-full transition-colors">
            {isBookmarked ? (
              <BookmarkCheck className="h-4 w-4 text-blue-600" />
            ) : (
              <Bookmark className="h-4 w-4 text-gray-400" />
            )}
          </button>
        </div>
      </div>
    </div>
  );
};

const ArticleGrid: React.FC<{
  articles: Article[];
  categoryName: string;
  onBookmark: (id: string) => void;
  bookmarkedArticles: Set<string>;
}> = ({ articles, categoryName, onBookmark, bookmarkedArticles }) => {
  const [viewMode, setViewMode] = useState<'grid' | 'list'>('grid');
  const [sortBy, setSortBy] = useState('newest');
  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <div>
          <h2 className="text-2xl font-bold text-white">
            {categoryName} Articles ({articles.length})
          </h2>
          <p className="text-gray-400 mt-1">Latest articles and insights in {categoryName.toLowerCase()}</p>
        </div>
        <div className="flex items-center space-x-4">
          <div className="flex items-center space-x-2">
            <Filter className="h-4 w-4 text-gray-400" />
            <select
              value={sortBy}
              onChange={(e) => setSortBy(e.target.value)}
              className="bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-white text-sm focus:outline-none focus:border-blue-500"
            >
              <option value="newest">Newest</option>
              <option value="oldest">Oldest</option>
              <option value="trending">Trending</option>
            </select>
          </div>
          <div className="flex bg-gray-800 rounded-lg p-1">
            <button
              onClick={() => setViewMode('grid')}
              className={`p-2 rounded ${viewMode === 'grid' ? 'bg-blue-600 text-white' : 'text-gray-400 hover:text-white'}`}
            >
              <Grid className="h-4 w-4" />
            </button>
            <button
              onClick={() => setViewMode('list')}
              className={`p-2 rounded ${viewMode === 'list' ? 'bg-blue-600 text-white' : 'text-gray-400 hover:text-white'}`}
            >
              <List className="h-4 w-4" />
            </button>
          </div>
        </div>
      </div>
      <div className={viewMode === 'grid' ? 'grid md:grid-cols-2 lg:grid-cols-3 gap-6' : 'space-y-4'}>
        {articles.map((article) => (
          <ArticleCard key={article.id} article={article} onBookmark={onBookmark} isBookmarked={bookmarkedArticles.has(article.id)} />
        ))}
      </div>
    </div>
  );
};

const BlockchainNewsInterface: React.FC = () => {
  const [isDark, setIsDark] = useState(true);
  const [currentCategory, setCurrentCategory] = useState<string>('technology-updates');
  const [bookmarkedArticles, setBookmarkedArticles] = useState<Set<string>>(new Set());

  const toggleTheme = () => setIsDark(!isDark);
  const handleBookmark = (articleId: string) => {
    const newBookmarks = new Set(bookmarkedArticles);
    if (newBookmarks.has(articleId)) newBookmarks.delete(articleId);
    else newBookmarks.add(articleId);
    setBookmarkedArticles(newBookmarks);
  };

  const filteredArticles = sampleArticles.filter(
    (article) => article.category === categories[currentCategory].name,
  );

  return (
    <div className={`min-h-screen ${isDark ? 'bg-black' : 'bg-gray-50'}`}>
      <CryptoTicker />
      <HeaderBar isDark={isDark} toggleTheme={toggleTheme} />
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <div className="mb-6">
          <button className="flex items-center text-gray-400 hover:text-white transition-colors">
            <ArrowLeft className="h-4 w-4 mr-2" /> Back to Home
          </button>
        </div>
        <CategoryHeroSection category={categories[currentCategory]} />
        <div className="mb-8">
          <div className="flex space-x-4 border-b border-gray-800">
            {Object.entries(categories).map(([key, category]) => (
              <button
                key={key}
                onClick={() => setCurrentCategory(key)}
                className={`pb-4 px-2 font-medium transition-colors border-b-2 ${
                  currentCategory === key ? 'border-blue-500 text-blue-400' : 'border-transparent text-gray-400 hover:text-white'
                }`}
              >
                {category.name}
              </button>
            ))}
          </div>
        </div>
        <ArticleGrid
          articles={filteredArticles}
          categoryName={categories[currentCategory].name}
          onBookmark={handleBookmark}
          bookmarkedArticles={bookmarkedArticles}
        />
      </main>
      <style jsx>{`
        @keyframes scroll {
          0% { transform: translateX(0); }
          100% { transform: translateX(-50%); }
        }
        .animate-scroll { animation: scroll 60s linear infinite; }
        .line-clamp-2 { overflow: hidden; display: -webkit-box; -webkit-box-orient: vertical; -webkit-line-clamp: 2; }
        .line-clamp-3 { overflow: hidden; display: -webkit-box; -webkit-box-orient: vertical; -webkit-line-clamp: 3; }
      `}</style>
    </div>
  );
};

export default BlockchainNewsInterface;
