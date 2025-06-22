import React from 'react';
import { Link } from 'react-router-dom';
import { Calendar, Clock, TrendingUp, Bookmark, BookmarkCheck } from 'lucide-react';
import { Card, CardContent, CardHeader } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { useAuth } from '@/contexts/AuthContext';

interface Article {
  id: string;
  title: string;
  slug: string;
  excerpt: string;
  category: string;
  author: {
    name: string;
    avatar: string;
  };
  publishedAt: string;
  readTime: string;
  image: string;
  tags: string[];
  featured: boolean;
  trending: boolean;
}

interface ArticleCardProps {
  article: Article;
  variant?: 'default' | 'trending' | 'featured' | 'compact';
}

const ArticleCard: React.FC<ArticleCardProps> = ({ article, variant = 'default' }) => {
  const { isAuthenticated, addBookmark, removeBookmark, isBookmarked } = useAuth();
  const bookmarked = isBookmarked(article.id);

  const handleBookmarkToggle = (e: React.MouseEvent) => {
    e.preventDefault();
    e.stopPropagation();
    
    if (!isAuthenticated) {
      // Could redirect to auth page or show login modal
      return;
    }

    if (bookmarked) {
      removeBookmark(article.id);
    } else {
      addBookmark(article.id);
    }
  };

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric'
    });
  };

  const getCategoryColor = (category: string) => {
    const colors: Record<string, string> = {
      'Market Analysis': 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200',
      'DeFi': 'bg-purple-100 text-purple-800 dark:bg-purple-900 dark:text-purple-200',
      'NFTs': 'bg-orange-100 text-orange-800 dark:bg-orange-900 dark:text-orange-200',
      'Regulations': 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200',
      'Technology Updates': 'bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200',
      'Institutional': 'bg-gray-100 text-gray-800 dark:bg-gray-900 dark:text-gray-200',
    };
    return colors[category] || 'bg-gray-100 text-gray-800 dark:bg-gray-900 dark:text-gray-200';
  };

  if (variant === 'compact') {
    return (
      <Link to={`/article/${article.slug}`} className="block">
        <Card className="hover:shadow-md transition-shadow cursor-pointer">
          <CardContent className="p-4">
            <div className="flex gap-4">
              <img
                src={article.image}
                alt={article.title}
                loading="lazy"
                width={80}
                height={80}
                className="w-20 h-20 object-cover rounded flex-shrink-0"
              />
              <div className="flex-1 min-w-0">
                <Badge className={`mb-2 ${getCategoryColor(article.category)}`}>
                  {article.category}
                </Badge>
                <h3 className="font-semibold text-sm line-clamp-2 mb-1">
                  {article.title}
                </h3>
                <div className="flex items-center text-xs text-muted-foreground">
                  <Calendar className="h-3 w-3 mr-1" />
                  <span>{formatDate(article.publishedAt)}</span>
                </div>
              </div>
            </div>
          </CardContent>
        </Card>
      </Link>
    );
  }

  return (
    <Card className="overflow-hidden hover:shadow-lg transition-all duration-300 group">
      <div className="relative">
        <Link to={`/article/${article.slug}`}>
          <img
            src={article.image}
            alt={article.title}
            loading="lazy"
            width={400}
            height={192}
            className="w-full h-48 object-cover group-hover:scale-105 transition-transform duration-300"
          />
        </Link>
        
        {/* Overlay Badges */}
        <div className="absolute top-4 left-4 flex gap-2">
          <Badge className={getCategoryColor(article.category)}>
            {article.category}
          </Badge>
          {article.trending && (
            <Badge className="bg-orange-100 text-orange-800 dark:bg-orange-900 dark:text-orange-200">
              <TrendingUp className="h-3 w-3 mr-1" />
              Trending
            </Badge>
          )}
        </div>

        {/* Bookmark Button */}
        {isAuthenticated && (
          <Button
            variant="ghost"
            size="sm"
            className="absolute top-4 right-4 h-8 w-8 bg-white/80 hover:bg-white dark:bg-black/80 dark:hover:bg-black backdrop-blur-sm"
            onClick={handleBookmarkToggle}
          >
            {bookmarked ? (
              <BookmarkCheck className="h-4 w-4 text-blue-600" />
            ) : (
              <Bookmark className="h-4 w-4" />
            )}
          </Button>
        )}
      </div>

      <CardContent className="p-6">
        <Link to={`/article/${article.slug}`} className="block">
          <h3 className="font-bold text-lg mb-3 line-clamp-2 group-hover:text-primary transition-colors">
            {article.title}
          </h3>
          
          <p className="text-muted-foreground mb-4 line-clamp-3 leading-relaxed">
            {article.excerpt}
          </p>

          {/* Article Meta */}
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-3">
              <img
                src={article.author.avatar || '/images/avatars/default.jpg'}
                alt={article.author.name}
                loading="lazy"
                width={32}
                height={32}
                className="w-8 h-8 rounded-full object-cover"
                onError={(e) => {
                  e.currentTarget.src = '/images/avatars/default.jpg';
                }}
              />
              <div>
                <p className="text-sm font-medium">{article.author.name}</p>
                <div className="flex items-center space-x-2 text-xs text-muted-foreground">
                  <div className="flex items-center space-x-1">
                    <Calendar className="h-3 w-3" />
                    <span>{formatDate(article.publishedAt)}</span>
                  </div>
                  <span>•</span>
                  <div className="flex items-center space-x-1">
                    <Clock className="h-3 w-3" />
                    <span>{article.readTime}</span>
                  </div>
                </div>
              </div>
            </div>
          </div>

          {/* Tags */}
          {article.tags && article.tags.length > 0 && (
            <div className="flex flex-wrap gap-1 mt-4">
              {article.tags.slice(0, 3).map((tag) => (
                <Badge key={tag} variant="outline" className="text-xs">
                  {tag}
                </Badge>
              ))}
              {article.tags.length > 3 && (
                <Badge variant="outline" className="text-xs">
                  +{article.tags.length - 3} more
                </Badge>
              )}
            </div>
          )}
        </Link>
      </CardContent>
    </Card>
  );
};

export default ArticleCard;
