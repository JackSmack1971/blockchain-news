import React, { useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import { ArrowLeft, Filter, Grid, List } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { Badge } from '@/components/ui/badge';
import { useData } from '@/contexts/DataContext';
import ArticleCard from '@/components/ui/ArticleCard';
import LoadingSpinner from '@/components/ui/LoadingSpinner';

const CategoryPage: React.FC = () => {
  const { categorySlug } = useParams<{ categorySlug: string }>();
  const { getArticlesByCategory, categories, isLoading } = useData();
  const [sortBy, setSortBy] = useState('newest');
  const [viewMode, setViewMode] = useState<'grid' | 'list'>('grid');

  const category = categories.find(cat => cat.slug === categorySlug);
  const categoryArticles = category ? getArticlesByCategory(category.name) : [];

  const sortedArticles = [...categoryArticles].sort((a, b) => {
    switch (sortBy) {
      case 'newest':
        return new Date(b.publishedAt).getTime() - new Date(a.publishedAt).getTime();
      case 'oldest':
        return new Date(a.publishedAt).getTime() - new Date(b.publishedAt).getTime();
      case 'trending':
        return Number(b.trending) - Number(a.trending);
      case 'featured':
        return Number(b.featured) - Number(a.featured);
      default:
        return 0;
    }
  });

  if (isLoading) {
    return <LoadingSpinner text="Loading category..." />;
  }

  if (!category) {
    return (
      <div className="container mx-auto px-4 py-8">
        <div className="text-center">
          <h2 className="text-2xl font-bold mb-4">Category Not Found</h2>
          <p className="text-muted-foreground mb-6">
            The category you're looking for doesn't exist.
          </p>
          <Button asChild>
            <Link to="/">
              <ArrowLeft className="h-4 w-4 mr-2" />
              Back to Home
            </Link>
          </Button>
        </div>
      </div>
    );
  }

  const getCategoryColor = (categoryName: string) => {
    const colors: Record<string, string> = {
      'Market Analysis': 'from-green-500 to-emerald-600',
      'DeFi': 'from-purple-500 to-violet-600',
      'NFTs': 'from-orange-500 to-amber-600',
      'Regulations': 'from-red-500 to-rose-600',
      'Technology Updates': 'from-blue-500 to-indigo-600',
      'Institutional': 'from-gray-500 to-slate-600',
    };
    return colors[categoryName] || 'from-gray-500 to-slate-600';
  };

  const getCategoryStats = () => {
    const totalArticles = categoryArticles.length;
    const featuredCount = categoryArticles.filter(article => article.featured).length;
    const trendingCount = categoryArticles.filter(article => article.trending).length;
    
    const latestArticle = categoryArticles
      .sort((a, b) => new Date(b.publishedAt).getTime() - new Date(a.publishedAt).getTime())[0];
    
    return {
      total: totalArticles,
      featured: featuredCount,
      trending: trendingCount,
      lastUpdated: latestArticle ? new Date(latestArticle.publishedAt).toLocaleDateString() : null,
    };
  };

  const stats = getCategoryStats();

  return (
    <div className="container mx-auto px-4 py-8">
      {/* Back Button */}
      <Button variant="ghost" asChild className="mb-6">
        <Link to="/">
          <ArrowLeft className="h-4 w-4 mr-2" />
          Back to Home
        </Link>
      </Button>

      {/* Category Header */}
      <div className={`bg-gradient-to-r ${getCategoryColor(category.name)} rounded-lg p-8 mb-8 text-white`}>
        <div className="max-w-3xl">
          <Badge variant="secondary" className="mb-4 bg-white/20 text-white border-white/30">
            Category
          </Badge>
          <h1 className="text-4xl font-bold mb-4">{category.name}</h1>
          <p className="text-lg opacity-90 leading-relaxed">
            {category.description}
          </p>
          
          {/* Category Stats */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mt-6">
            <div className="bg-white/10 rounded-lg p-3 backdrop-blur-sm">
              <div className="text-2xl font-bold">{stats.total}</div>
              <div className="text-sm opacity-75">Total Articles</div>
            </div>
            <div className="bg-white/10 rounded-lg p-3 backdrop-blur-sm">
              <div className="text-2xl font-bold">{stats.featured}</div>
              <div className="text-sm opacity-75">Featured</div>
            </div>
            <div className="bg-white/10 rounded-lg p-3 backdrop-blur-sm">
              <div className="text-2xl font-bold">{stats.trending}</div>
              <div className="text-sm opacity-75">Trending</div>
            </div>
            <div className="bg-white/10 rounded-lg p-3 backdrop-blur-sm">
              <div className="text-sm font-medium">Last Updated</div>
              <div className="text-sm opacity-75">{stats.lastUpdated || 'N/A'}</div>
            </div>
          </div>
        </div>
      </div>

      {/* Controls */}
      <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4 mb-8">
        <div>
          <h2 className="text-2xl font-bold">
            {category.name} Articles ({sortedArticles.length})
          </h2>
          <p className="text-muted-foreground">
            Latest articles and insights in {category.name.toLowerCase()}
          </p>
        </div>
        
        <div className="flex items-center gap-4">
          {/* Sort Options */}
          <Select value={sortBy} onValueChange={setSortBy}>
            <SelectTrigger className="w-[140px]">
              <Filter className="h-4 w-4 mr-2" />
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="newest">Newest</SelectItem>
              <SelectItem value="oldest">Oldest</SelectItem>
              <SelectItem value="trending">Trending</SelectItem>
              <SelectItem value="featured">Featured</SelectItem>
            </SelectContent>
          </Select>

          {/* View Mode Toggle */}
          <div className="flex items-center border rounded-lg">
            <Button
              variant={viewMode === 'grid' ? 'default' : 'ghost'}
              size="sm"
              onClick={() => setViewMode('grid')}
              className="rounded-r-none"
            >
              <Grid className="h-4 w-4" />
            </Button>
            <Button
              variant={viewMode === 'list' ? 'default' : 'ghost'}
              size="sm"
              onClick={() => setViewMode('list')}
              className="rounded-l-none"
            >
              <List className="h-4 w-4" />
            </Button>
          </div>
        </div>
      </div>

      {/* Articles Content */}
      {sortedArticles.length > 0 ? (
        <div className={
          viewMode === 'grid' 
            ? 'grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6'
            : 'space-y-6'
        }>
          {sortedArticles.map((article) => (
            <ArticleCard 
              key={article.id} 
              article={article} 
              variant={viewMode === 'list' ? 'default' : 'default'}
            />
          ))}
        </div>
      ) : (
        <Card>
          <CardContent className="p-12 text-center">
            <h3 className="text-lg font-semibold mb-2">No Articles Found</h3>
            <p className="text-muted-foreground mb-6">
              There are no articles in the {category.name} category yet.
            </p>
            <Button asChild>
              <Link to="/">Browse All Articles</Link>
            </Button>
          </CardContent>
        </Card>
      )}

      {/* Related Categories */}
      {categories.length > 1 && (
        <Card className="mt-12">
          <CardHeader>
            <CardTitle>Explore Other Categories</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {categories
                .filter(cat => cat.id !== category.id)
                .map((relatedCategory) => (
                  <Link
                    key={relatedCategory.id}
                    to={`/category/${relatedCategory.slug}`}
                    className="block p-4 border rounded-lg hover:bg-muted/50 transition-colors"
                  >
                    <h4 className="font-semibold mb-2">{relatedCategory.name}</h4>
                    <p className="text-sm text-muted-foreground line-clamp-2">
                      {relatedCategory.description}
                    </p>
                  </Link>
                ))}
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
};

export default CategoryPage;
