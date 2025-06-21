import React, { createContext, useContext, useState, useEffect } from 'react';

interface Article {
  id: string;
  title: string;
  slug: string;
  excerpt: string;
  content: string;
  category: string;
  author: {
    name: string;
    bio: string;
    avatar: string;
  };
  publishedAt: string;
  readTime: string;
  image: string;
  tags: string[];
  featured: boolean;
  trending: boolean;
}

interface MarketCoin {
  id: string;
  symbol: string;
  name: string;
  price: number;
  change_24h: number;
  market_cap: number;
  volume_24h: number;
  circulating_supply: number;
  logo: string;
}

interface MarketData {
  coins: MarketCoin[];
  global_stats: {
    total_market_cap: number;
    total_volume_24h: number;
    market_cap_change_24h: number;
    bitcoin_dominance: number;
    ethereum_dominance: number;
    defi_market_cap: number;
    defi_dominance: number;
  };
  fear_greed_index: {
    value: number;
    classification: string;
    last_updated: string;
  };
  trending_searches: string[];
}

interface Category {
  id: string;
  name: string;
  slug: string;
  description: string;
  color: string;
  icon: string;
}

interface TrendingTopic {
  id: string;
  topic: string;
  mentions: number;
  change: number;
  sentiment: 'positive' | 'negative' | 'neutral';
}

interface DataContextType {
  articles: Article[];
  marketData: MarketData | null;
  categories: Category[];
  trendingTopics: TrendingTopic[];
  isLoading: boolean;
  error: string | null;
  searchArticles: (query: string) => Article[];
  getArticleBySlug: (slug: string) => Article | undefined;
  getArticlesByCategory: (category: string) => Article[];
  getFeaturedArticles: () => Article[];
  getTrendingArticles: () => Article[];
  refreshMarketData: () => Promise<void>;
}

const DataContext = createContext<DataContextType | undefined>(undefined);

export const useData = () => {
  const context = useContext(DataContext);
  if (!context) {
    throw new Error('useData must be used within a DataProvider');
  }
  return context;
};

export const DataProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [articles, setArticles] = useState<Article[]>([]);
  const [marketData, setMarketData] = useState<MarketData | null>(null);
  const [categories, setCategories] = useState<Category[]>([]);
  const [trendingTopics, setTrendingTopics] = useState<TrendingTopic[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Load initial data
  useEffect(() => {
    loadInitialData();
  }, []);

  const loadInitialData = async () => {
    setIsLoading(true);
    setError(null);
    
    try {
      const [articlesResponse, marketResponse, categoriesResponse, trendingResponse] = await Promise.all([
        fetch('/data/articles.json'),
        fetch('/data/market-data.json'),
        fetch('/data/categories.json'),
        fetch('/data/trending-topics.json'),
      ]);

      if (!articlesResponse.ok || !marketResponse.ok || !categoriesResponse.ok || !trendingResponse.ok) {
        throw new Error('Failed to load data');
      }

      const [articlesData, marketDataResponse, categoriesData, trendingData] = await Promise.all([
        articlesResponse.json(),
        marketResponse.json(),
        categoriesResponse.json(),
        trendingResponse.json(),
      ]);

      setArticles(articlesData);
      setMarketData(marketDataResponse);
      setCategories(categoriesData);
      setTrendingTopics(trendingData);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An error occurred');
      console.error('Error loading data:', err);
    } finally {
      setIsLoading(false);
    }
  };

  const refreshMarketData = async () => {
    try {
      // Simulate real-time market data updates
      if (marketData) {
        const updatedMarketData = {
          ...marketData,
          coins: marketData.coins.map(coin => ({
            ...coin,
            price: coin.price * (1 + (Math.random() - 0.5) * 0.02), // ±1% random change
            change_24h: coin.change_24h + (Math.random() - 0.5) * 2, // ±1% change
          })),
          global_stats: {
            ...marketData.global_stats,
            market_cap_change_24h: marketData.global_stats.market_cap_change_24h + (Math.random() - 0.5) * 1,
          },
        };
        setMarketData(updatedMarketData);
      }
    } catch (err) {
      console.error('Error refreshing market data:', err);
    }
  };

  // Auto-refresh market data every 30 seconds
  useEffect(() => {
    const interval = setInterval(refreshMarketData, 30000);
    return () => clearInterval(interval);
  }, [marketData]);

  const searchArticles = (query: string): Article[] => {
    if (!query.trim()) return articles;
    
    const lowercaseQuery = query.toLowerCase();
    return articles.filter(article =>
      article.title.toLowerCase().includes(lowercaseQuery) ||
      article.excerpt.toLowerCase().includes(lowercaseQuery) ||
      article.content.toLowerCase().includes(lowercaseQuery) ||
      article.tags.some(tag => tag.toLowerCase().includes(lowercaseQuery)) ||
      article.author.name.toLowerCase().includes(lowercaseQuery)
    );
  };

  const getArticleBySlug = (slug: string): Article | undefined => {
    return articles.find(article => article.slug === slug);
  };

  const getArticlesByCategory = (category: string): Article[] => {
    return articles.filter(article => 
      article.category.toLowerCase() === category.toLowerCase()
    );
  };

  const getFeaturedArticles = (): Article[] => {
    return articles.filter(article => article.featured);
  };

  const getTrendingArticles = (): Article[] => {
    return articles.filter(article => article.trending);
  };

  const value: DataContextType = {
    articles,
    marketData,
    categories,
    trendingTopics,
    isLoading,
    error,
    searchArticles,
    getArticleBySlug,
    getArticlesByCategory,
    getFeaturedArticles,
    getTrendingArticles,
    refreshMarketData,
  };

  return <DataContext.Provider value={value}>{children}</DataContext.Provider>;
};
