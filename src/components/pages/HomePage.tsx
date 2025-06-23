import React, { useState, useEffect, lazy, Suspense } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { Calendar, Clock, TrendingUp, Star, Search, Filter } from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { useData } from '@/contexts/DataContext';
import ArticleCard from '@/components/ui/ArticleCard';
import LoadingSpinner from '@/components/ui/LoadingSpinner';
import { searchSchema } from '@/lib/validation';
const TrendingSidebar = lazy(() => import('@/components/ui/TrendingSidebar'));

const HomePage: React.FC = () => {
  const [searchParams] = useSearchParams();
  const { 
    articles, 
    getFeaturedArticles, 
    getTrendingArticles, 
    searchArticles, 
    categories, 
    isLoading, 
    error 
  } = useData();
  
  const [searchQuery, setSearchQuery] = useState(searchParams.get('search') || '');
  const [selectedCategory, setSelectedCategory] = useState('all');
  const [sortBy, setSortBy] = useState('newest');
  const [filteredArticles, setFilteredArticles] = useState(articles);

  useEffect(() => {
    let result = articles;

    // Apply search filter
    if (searchQuery.trim()) {
      result = searchArticles(searchQuery);
    }

    // Apply category filter
    if (selectedCategory !== 'all') {
      result = result.filter(article => 
        article.category.toLowerCase() === selectedCategory.toLowerCase()
      );
    }

    // Apply sorting
    result = [...result].sort((a, b) => {
      switch (sortBy) {
        case 'newest':
          return new Date(b.publishedAt).getTime() - new Date(a.publishedAt).getTime();
        case 'oldest':
          return new Date(a.publishedAt).getTime() - new Date(b.publishedAt).getTime();
        case 'trending':
          return Number(b.trending) - Number(a.trending);
        default:
          return 0;
      }
    });

    setFilteredArticles(result);
  }, [articles, searchQuery, selectedCategory, sortBy, searchArticles]);

  // Update search query from URL params
  useEffect(() => {
    const urlSearch = searchParams.get('search');
    if (urlSearch) {
      setSearchQuery(urlSearch);
    }
  }, [searchParams]);

  const featuredArticles = getFeaturedArticles();
  const trendingArticles = getTrendingArticles();

  if (isLoading) {
    return <LoadingSpinner />;
  }

  if (error) {
    return (
      <div className="container mx-auto px-4 py-8">
        <div className="text-center">
          <h2 className="text-2xl font-bold text-destructive mb-4">Error Loading Content</h2>
          <p className="text-muted-foreground">{error}</p>
        </div>
      </div>
    );
  }

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric'
    });
  };

  return (
    <div className="min-h-screen bg-background">
      {/* Hero Section */}
      {!searchQuery && featuredArticles.length > 0 && (
        <section className="bg-gradient-to-br from-blue-50 to-purple-50 dark:from-blue-950/30 dark:to-purple-950/30 border-b">
          <div className="container mx-auto px-4 py-12">
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 items-center">
              <div>
                <Badge className="mb-4 bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200">
                  <Star className="h-3 w-3 mr-1" />
                  Featured Story
                </Badge>
                <h1 className="text-4xl md:text-5xl font-bold mb-4 leading-tight">
                  {featuredArticles[0].title}
                </h1>
                <p className="text-lg text-muted-foreground mb-6 leading-relaxed">
                  {featuredArticles[0].excerpt}
                </p>
                <div className="flex items-center space-x-4 mb-6">
                  <div className="flex items-center space-x-2 text-sm text-muted-foreground">
                    <Calendar className="h-4 w-4" />
                    <span>{formatDate(featuredArticles[0].publishedAt)}</span>
                  </div>
                  <div className="flex items-center space-x-2 text-sm text-muted-foreground">
                    <Clock className="h-4 w-4" />
                    <span>{featuredArticles[0].readTime}</span>
                  </div>
                </div>
                <Button asChild size="lg">
                  <Link to={`/article/${featuredArticles[0].slug}`}>
                    Read Full Article
                  </Link>
                </Button>
              </div>
              <div className="relative">
                <img
                  src={featuredArticles[0].image}
                  alt={featuredArticles[0].title}
                  loading="lazy"
                  width={1200}
                  height={400}
                  className="w-full h-[300px] md:h-[400px] object-cover rounded-lg shadow-lg"
                />
                <div className="absolute top-4 right-4">
                  <Badge variant="secondary" className="bg-white/90 text-gray-800">
                    {featuredArticles[0].category}
                  </Badge>
                </div>
              </div>
            </div>
          </div>
        </section>
      )}

      {/* Main Content */}
      <div className="container mx-auto px-4 py-8">
        <div className="grid grid-cols-1 lg:grid-cols-4 gap-8">
          {/* Main Content Area */}
          <div className="lg:col-span-3">
            {/* Search and Filters */}
            <div className="mb-8">
              <div className="flex flex-col md:flex-row gap-4 mb-6">
                <div className="relative flex-1">
                  <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-muted-foreground h-4 w-4" />
                  <Input
                    type="search"
                    placeholder="Search articles..."
                    value={searchQuery}
                    onChange={(e) => {
                      const parsed = searchSchema.safeParse({ query: e.target.value });
                      setSearchQuery(parsed.success ? parsed.data.query : e.target.value.slice(0, 100));
                    }}
                    className="pl-10"
                  />
                </div>
                <Select value={selectedCategory} onValueChange={setSelectedCategory}>
                  <SelectTrigger className="w-full md:w-[180px]">
                    <Filter className="h-4 w-4 mr-2" />
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">All Categories</SelectItem>
                    {categories.map((category) => (
                      <SelectItem key={category.id} value={category.name}>
                        {category.name}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                <Select value={sortBy} onValueChange={setSortBy}>
                  <SelectTrigger className="w-full md:w-[120px]">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="newest">Newest</SelectItem>
                    <SelectItem value="oldest">Oldest</SelectItem>
                    <SelectItem value="trending">Trending</SelectItem>
                  </SelectContent>
                </Select>
              </div>

              {/* Search Results Info */}
              {searchQuery && (
                <div className="mb-6">
                  <h2 className="text-xl font-semibold mb-2">
                    Search Results for "{searchQuery}"
                  </h2>
                  <p className="text-muted-foreground">
                    Found {filteredArticles.length} article{filteredArticles.length !== 1 ? 's' : ''}
                  </p>
                </div>
              )}
            </div>

            {/* Trending Articles Section */}
            {!searchQuery && trendingArticles.length > 0 && (
              <section className="mb-12">
                <div className="flex items-center space-x-2 mb-6">
                  <TrendingUp className="h-5 w-5 text-orange-500" />
                  <h2 className="text-2xl font-bold">Trending Now</h2>
                </div>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                  {trendingArticles.slice(0, 4).map((article) => (
                    <ArticleCard key={article.id} article={article} variant="trending" />
                  ))}
                </div>
              </section>
            )}

            {/* Latest Articles */}
            <section>
              <h2 className="text-2xl font-bold mb-6">
                {searchQuery ? 'Search Results' : 'Latest Articles'}
              </h2>
              
              {filteredArticles.length > 0 ? (
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                  {filteredArticles.map((article) => (
                    <ArticleCard key={article.id} article={article} />
                  ))}
                </div>
              ) : (
                <Card>
                  <CardContent className="p-8 text-center">
                    <h3 className="text-lg font-semibold mb-2">No articles found</h3>
                    <p className="text-muted-foreground mb-4">
                      {searchQuery 
                        ? `No articles match your search for "${searchQuery}"`
                        : 'No articles available in this category'
                      }
                    </p>
                    <Button 
                      variant="outline" 
                      onClick={() => {
                        setSearchQuery('');
                        setSelectedCategory('all');
                      }}
                    >
                      Clear Filters
                    </Button>
                  </CardContent>
                </Card>
              )}
            </section>
          </div>

          {/* Sidebar */}
          <div className="lg:col-span-1">
            <Suspense fallback={<div className="py-4 text-center">Loading...</div>}>
              <TrendingSidebar />
            </Suspense>
          </div>
        </div>
      </div>
    </div>
  );
};

export default HomePage;
