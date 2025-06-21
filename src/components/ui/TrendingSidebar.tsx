import React from 'react';
import { Link } from 'react-router-dom';
import { TrendingUp, TrendingDown, Hash, ArrowUpRight } from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { useData } from '@/contexts/DataContext';

const TrendingSidebar: React.FC = () => {
  const { trendingTopics, marketData, articles } = useData();

  const recentArticles = articles
    .sort((a, b) => new Date(b.publishedAt).getTime() - new Date(a.publishedAt).getTime())
    .slice(0, 5);

  const getSentimentIcon = (sentiment: string) => {
    switch (sentiment) {
      case 'positive':
        return <TrendingUp className="h-3 w-3 text-green-500" />;
      case 'negative':
        return <TrendingDown className="h-3 w-3 text-red-500" />;
      default:
        return <Hash className="h-3 w-3 text-gray-500" />;
    }
  };

  const getSentimentColor = (sentiment: string) => {
    switch (sentiment) {
      case 'positive':
        return 'text-green-600 dark:text-green-400';
      case 'negative':
        return 'text-red-600 dark:text-red-400';
      default:
        return 'text-muted-foreground';
    }
  };

  const formatPrice = (price: number) => {
    if (price >= 1000) {
      return `$${price.toLocaleString(undefined, { maximumFractionDigits: 0 })}`;
    }
    return `$${price.toFixed(2)}`;
  };

  const formatChange = (change: number) => {
    return `${change >= 0 ? '+' : ''}${change.toFixed(2)}%`;
  };

  return (
    <div className="space-y-6 sticky top-24">
      {/* Trending Topics */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center space-x-2">
            <TrendingUp className="h-5 w-5 text-orange-500" />
            <span>Trending Topics</span>
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          {trendingTopics.slice(0, 8).map((topic) => (
            <div key={topic.id} className="flex items-center justify-between">
              <div className="flex items-center space-x-2 flex-1 min-w-0">
                {getSentimentIcon(topic.sentiment)}
                <span className="text-sm font-medium truncate">{topic.topic}</span>
              </div>
              <div className="text-right text-xs">
                <div className="text-muted-foreground">{topic.mentions.toLocaleString()}</div>
                <div className={`flex items-center space-x-1 ${getSentimentColor(topic.sentiment)}`}>
                  <span>{formatChange(topic.change)}</span>
                  {topic.change >= 0 ? (
                    <TrendingUp className="h-3 w-3" />
                  ) : (
                    <TrendingDown className="h-3 w-3" />
                  )}
                </div>
              </div>
            </div>
          ))}
        </CardContent>
      </Card>

      {/* Top Cryptocurrencies */}
      {marketData && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center justify-between">
              <span>Top Cryptos</span>
              <Button variant="ghost" size="sm" asChild>
                <Link to="/market-data">
                  <ArrowUpRight className="h-4 w-4" />
                </Link>
              </Button>
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            {marketData.coins.slice(0, 5).map((coin) => (
              <div key={coin.id} className="flex items-center justify-between">
                <div className="flex items-center space-x-2">
                  <img
                    src={coin.logo}
                    alt={coin.name}
                    className="w-6 h-6 rounded-full"
                    onError={(e) => {
                      e.currentTarget.src = '/images/crypto-placeholder.png';
                    }}
                  />
                  <div>
                    <div className="font-medium text-sm">{coin.symbol}</div>
                    <div className="text-xs text-muted-foreground">{coin.name}</div>
                  </div>
                </div>
                <div className="text-right">
                  <div className="text-sm font-medium">{formatPrice(coin.price)}</div>
                  <div className={`text-xs ${
                    coin.change_24h >= 0 
                      ? 'text-green-600 dark:text-green-400' 
                      : 'text-red-600 dark:text-red-400'
                  }`}>
                    {formatChange(coin.change_24h)}
                  </div>
                </div>
              </div>
            ))}
          </CardContent>
        </Card>
      )}

      {/* Market Stats */}
      {marketData && (
        <Card>
          <CardHeader>
            <CardTitle>Market Overview</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <div className="flex justify-between items-center">
              <span className="text-sm text-muted-foreground">Total Market Cap</span>
              <span className="text-sm font-medium">
                ${(marketData.global_stats.total_market_cap / 1e12).toFixed(2)}T
              </span>
            </div>
            <div className="flex justify-between items-center">
              <span className="text-sm text-muted-foreground">24h Volume</span>
              <span className="text-sm font-medium">
                ${(marketData.global_stats.total_volume_24h / 1e9).toFixed(1)}B
              </span>
            </div>
            <div className="flex justify-between items-center">
              <span className="text-sm text-muted-foreground">BTC Dominance</span>
              <span className="text-sm font-medium">
                {marketData.global_stats.bitcoin_dominance.toFixed(1)}%
              </span>
            </div>
            <div className="flex justify-between items-center">
              <span className="text-sm text-muted-foreground">Fear & Greed</span>
              <Badge variant={
                marketData.fear_greed_index.value > 75 ? 'destructive' :
                marketData.fear_greed_index.value > 50 ? 'default' : 'secondary'
              }>
                {marketData.fear_greed_index.value} - {marketData.fear_greed_index.classification}
              </Badge>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Recent Articles */}
      <Card>
        <CardHeader>
          <CardTitle>Recent Articles</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          {recentArticles.map((article) => (
            <Link 
              key={article.id} 
              to={`/article/${article.slug}`}
              className="block group"
            >
              <div className="flex gap-3">
                <img
                  src={article.image}
                  alt={article.title}
                  className="w-12 h-12 object-cover rounded flex-shrink-0"
                />
                <div className="flex-1 min-w-0">
                  <h4 className="text-sm font-medium line-clamp-2 group-hover:text-primary transition-colors">
                    {article.title}
                  </h4>
                  <p className="text-xs text-muted-foreground mt-1">
                    {new Date(article.publishedAt).toLocaleDateString()}
                  </p>
                </div>
              </div>
            </Link>
          ))}
        </CardContent>
      </Card>

      {/* Newsletter Signup */}
      <Card className="bg-gradient-to-br from-blue-50 to-purple-50 dark:from-blue-950/30 dark:to-purple-950/30">
        <CardHeader>
          <CardTitle className="text-center">Stay Updated</CardTitle>
        </CardHeader>
        <CardContent className="text-center space-y-4">
          <p className="text-sm text-muted-foreground">
            Get the latest crypto news and analysis delivered to your inbox.
          </p>
          <Button className="w-full" asChild>
            <Link to="/auth">Subscribe Now</Link>
          </Button>
        </CardContent>
      </Card>
    </div>
  );
};

export default TrendingSidebar;
