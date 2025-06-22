import React, { useState, useEffect } from 'react';
import { useParams, Link } from 'react-router-dom';
import { 
  Calendar, 
  Clock, 
  Share2, 
  Bookmark, 
  BookmarkCheck, 
  Twitter, 
  Facebook, 
  Linkedin,
  ArrowLeft,
  MessageCircle,
  ThumbsUp,
  ThumbsDown,
  Flag,
  User
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Separator } from '@/components/ui/separator';
import { Textarea } from '@/components/ui/textarea';
import { Avatar, AvatarFallback, AvatarImage } from '@/components/ui/avatar';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import { toast } from 'sonner';
import { useData } from '@/contexts/DataContext';
import { useAuth } from '@/contexts/AuthContext';
import LoadingSpinner from '@/components/ui/LoadingSpinner';
import ArticleCard from '@/components/ui/ArticleCard';
import { sanitizeHtml } from '@/lib/sanitizeHtml';

interface Comment {
  id: string;
  author: {
    name: string;
    avatar: string;
  };
  content: string;
  timestamp: string;
  likes: number;
  dislikes: number;
  replies?: Comment[];
}

const ArticlePage: React.FC = () => {
  const { articleSlug } = useParams<{ articleSlug: string }>();
  const { getArticleBySlug, articles } = useData();
  const { isAuthenticated, addBookmark, removeBookmark, isBookmarked, user } = useAuth();
  
  const [comments, setComments] = useState<Comment[]>([]);
  const [newComment, setNewComment] = useState('');
  const [isSubmittingComment, setIsSubmittingComment] = useState(false);

  const article = articleSlug ? getArticleBySlug(articleSlug) : null;
  const bookmarked = article ? isBookmarked(article.id) : false;

  // Get related articles (same category, excluding current article)
  const relatedArticles = article 
    ? articles
        .filter(a => a.category === article.category && a.id !== article.id)
        .slice(0, 3)
    : [];

  // Mock comments data
  useEffect(() => {
    if (article) {
      setComments([
        {
          id: '1',
          author: {
            name: 'Alex Chen',
            avatar: '/images/avatars/alex.jpg',
          },
          content: 'Great analysis! This really helps understand the market dynamics behind the recent price movements.',
          timestamp: '2025-06-22T04:30:00Z',
          likes: 12,
          dislikes: 1,
        },
        {
          id: '2',
          author: {
            name: 'Sarah Johnson',
            avatar: '/images/avatars/sarah-j.jpg',
          },
          content: 'I appreciate the detailed breakdown of the technical factors. The institutional adoption angle is particularly interesting.',
          timestamp: '2025-06-22T03:15:00Z',
          likes: 8,
          dislikes: 0,
        },
        {
          id: '3',
          author: {
            name: 'Michael Torres',
            avatar: '/images/avatars/michael.jpg',
          },
          content: 'While I agree with most points, I think the regulatory impact might be understated. What are your thoughts on the upcoming SEC decisions?',
          timestamp: '2025-06-22T02:45:00Z',
          likes: 15,
          dislikes: 2,
        },
      ]);
    }
  }, [article]);

  if (!article) {
    return (
      <div className="container mx-auto px-4 py-8">
        <div className="text-center">
          <h2 className="text-2xl font-bold mb-4">Article Not Found</h2>
          <p className="text-muted-foreground mb-6">
            The article you're looking for doesn't exist or has been removed.
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

  const handleBookmarkToggle = () => {
    if (!isAuthenticated) {
      toast.error('Please sign in to bookmark articles');
      return;
    }

    if (bookmarked) {
      removeBookmark(article.id);
      toast.success('Article removed from bookmarks');
    } else {
      addBookmark(article.id);
      toast.success('Article added to bookmarks');
    }
  };

  const handleShare = (platform: string) => {
    const url = window.location.href;
    const text = `${article.title} - ${article.excerpt}`;
    
    let shareUrl = '';
    
    switch (platform) {
      case 'twitter':
        shareUrl = `https://twitter.com/intent/tweet?text=${encodeURIComponent(text)}&url=${encodeURIComponent(url)}`;
        break;
      case 'facebook':
        shareUrl = `https://www.facebook.com/sharer/sharer.php?u=${encodeURIComponent(url)}`;
        break;
      case 'linkedin':
        shareUrl = `https://www.linkedin.com/sharing/share-offsite/?url=${encodeURIComponent(url)}`;
        break;
      case 'copy':
        navigator.clipboard.writeText(url);
        toast.success('Link copied to clipboard');
        return;
    }
    
    if (shareUrl) {
      window.open(shareUrl, '_blank', 'width=600,height=400');
    }
  };

  const handleCommentSubmit = async () => {
    if (!isAuthenticated) {
      toast.error('Please sign in to comment');
      return;
    }
    
    if (!newComment.trim()) {
      toast.error('Please enter a comment');
      return;
    }

    setIsSubmittingComment(true);
    
    // Simulate comment submission
    await new Promise(resolve => setTimeout(resolve, 1000));
    
    const comment: Comment = {
      id: Date.now().toString(),
      author: {
        name: user?.username || 'Anonymous',
        avatar: user?.avatar || '/images/avatars/default.jpg',
      },
      content: newComment,
      timestamp: new Date().toISOString(),
      likes: 0,
      dislikes: 0,
    };
    
    setComments(prev => [comment, ...prev]);
    setNewComment('');
    setIsSubmittingComment(false);
    toast.success('Comment posted successfully');
  };

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'long',
      day: 'numeric'
    });
  };

  const formatCommentDate = (dateString: string) => {
    const date = new Date(dateString);
    const now = new Date();
    const diffInHours = Math.floor((now.getTime() - date.getTime()) / (1000 * 60 * 60));
    
    if (diffInHours < 1) {
      return 'Just now';
    } else if (diffInHours < 24) {
      return `${diffInHours}h ago`;
    } else {
      const diffInDays = Math.floor(diffInHours / 24);
      return `${diffInDays}d ago`;
    }
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

  return (
    <div className="container mx-auto px-4 py-8">
      {/* Back Button */}
      <Button variant="ghost" asChild className="mb-6">
        <Link to="/">
          <ArrowLeft className="h-4 w-4 mr-2" />
          Back to Articles
        </Link>
      </Button>

      <div className="grid grid-cols-1 lg:grid-cols-4 gap-8">
        {/* Main Article Content */}
        <div className="lg:col-span-3">
          {/* Article Header */}
          <div className="mb-8">
            <Badge className={`mb-4 ${getCategoryColor(article.category)}`}>
              {article.category}
            </Badge>
            
            <h1 className="text-4xl font-bold mb-4 leading-tight">
              {article.title}
            </h1>
            
            <p className="text-xl text-muted-foreground mb-6 leading-relaxed">
              {article.excerpt}
            </p>

            {/* Article Meta */}
            <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 mb-6">
              <div className="flex items-center space-x-4">
                <Avatar>
                  <AvatarImage src={article.author.avatar} />
                  <AvatarFallback>{article.author.name.charAt(0)}</AvatarFallback>
                </Avatar>
                <div>
                  <p className="font-medium">{article.author.name}</p>
                  <div className="flex items-center space-x-2 text-sm text-muted-foreground">
                    <Calendar className="h-4 w-4" />
                    <span>{formatDate(article.publishedAt)}</span>
                    <span>•</span>
                    <Clock className="h-4 w-4" />
                    <span>{article.readTime}</span>
                  </div>
                </div>
              </div>

              {/* Action Buttons */}
              <div className="flex items-center space-x-2">
                <Button
                  variant="outline"
                  size="sm"
                  onClick={handleBookmarkToggle}
                  className="flex items-center space-x-2"
                >
                  {bookmarked ? (
                    <BookmarkCheck className="h-4 w-4 text-blue-600" />
                  ) : (
                    <Bookmark className="h-4 w-4" />
                  )}
                  <span>{bookmarked ? 'Saved' : 'Save'}</span>
                </Button>

                <DropdownMenu>
                  <DropdownMenuTrigger asChild>
                    <Button variant="outline" size="sm">
                      <Share2 className="h-4 w-4 mr-2" />
                      Share
                    </Button>
                  </DropdownMenuTrigger>
                  <DropdownMenuContent align="end">
                    <DropdownMenuItem onClick={() => handleShare('twitter')}>
                      <Twitter className="h-4 w-4 mr-2" />
                      Twitter
                    </DropdownMenuItem>
                    <DropdownMenuItem onClick={() => handleShare('facebook')}>
                      <Facebook className="h-4 w-4 mr-2" />
                      Facebook
                    </DropdownMenuItem>
                    <DropdownMenuItem onClick={() => handleShare('linkedin')}>
                      <Linkedin className="h-4 w-4 mr-2" />
                      LinkedIn
                    </DropdownMenuItem>
                    <DropdownMenuItem onClick={() => handleShare('copy')}>
                      <Share2 className="h-4 w-4 mr-2" />
                      Copy Link
                    </DropdownMenuItem>
                  </DropdownMenuContent>
                </DropdownMenu>
              </div>
            </div>

            {/* Featured Image */}
            <img
              src={article.image}
              alt={article.title}
              className="w-full h-[400px] object-cover rounded-lg mb-8"
            />
          </div>

          {/* Article Content */}
          <div className="article-content mb-12">
            {article.content.split('\n\n').map((paragraph, index) => (
              <p
                key={index}
                className="mb-6 leading-relaxed"
                dangerouslySetInnerHTML={{
                  __html: sanitizeHtml(paragraph),
                }}
              />
            ))}
          </div>

          {/* Tags */}
          {article.tags && article.tags.length > 0 && (
            <div className="mb-8">
              <h3 className="text-lg font-semibold mb-4">Tags</h3>
              <div className="flex flex-wrap gap-2">
                {article.tags.map((tag) => (
                  <Badge key={tag} variant="outline">
                    {tag}
                  </Badge>
                ))}
              </div>
            </div>
          )}

          <Separator className="mb-8" />

          {/* Author Bio */}
          <Card className="mb-8">
            <CardContent className="p-6">
              <div className="flex items-start space-x-4">
                <Avatar className="h-16 w-16">
                  <AvatarImage src={article.author.avatar} />
                  <AvatarFallback>{article.author.name.charAt(0)}</AvatarFallback>
                </Avatar>
                <div className="flex-1">
                  <h4 className="text-lg font-semibold mb-2">{article.author.name}</h4>
                  <p className="text-muted-foreground leading-relaxed">
                    {article.author.bio}
                  </p>
                </div>
              </div>
            </CardContent>
          </Card>

          {/* Comments Section */}
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center space-x-2">
                <MessageCircle className="h-5 w-5" />
                <span>Comments ({comments.length})</span>
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-6">
              {/* Comment Form */}
              {isAuthenticated ? (
                <div className="space-y-4">
                  <Textarea
                    placeholder="Share your thoughts..."
                    value={newComment}
                    onChange={(e) => setNewComment(e.target.value)}
                    rows={3}
                  />
                  <div className="flex justify-end">
                    <Button 
                      onClick={handleCommentSubmit}
                      disabled={isSubmittingComment || !newComment.trim()}
                    >
                      {isSubmittingComment ? 'Posting...' : 'Post Comment'}
                    </Button>
                  </div>
                </div>
              ) : (
                <div className="text-center py-8">
                  <p className="text-muted-foreground mb-4">
                    Please sign in to comment on this article
                  </p>
                  <Button asChild>
                    <Link to="/auth">Sign In</Link>
                  </Button>
                </div>
              )}

              <Separator />

              {/* Comments List */}
              <div className="space-y-6">
                {comments.map((comment) => (
                  <div key={comment.id} className="flex space-x-4">
                    <Avatar>
                      <AvatarImage src={comment.author.avatar} />
                      <AvatarFallback>{comment.author.name.charAt(0)}</AvatarFallback>
                    </Avatar>
                    <div className="flex-1">
                      <div className="flex items-center space-x-2 mb-2">
                        <span className="font-medium">{comment.author.name}</span>
                        <span className="text-sm text-muted-foreground">
                          {formatCommentDate(comment.timestamp)}
                        </span>
                      </div>
                      <p
                        className="text-muted-foreground mb-3 leading-relaxed"
                        dangerouslySetInnerHTML={{
                          __html: sanitizeHtml(comment.content),
                        }}
                      />
                      <div className="flex items-center space-x-4">
                        <Button variant="ghost" size="sm" className="h-8 px-2">
                          <ThumbsUp className="h-3 w-3 mr-1" />
                          {comment.likes}
                        </Button>
                        <Button variant="ghost" size="sm" className="h-8 px-2">
                          <ThumbsDown className="h-3 w-3 mr-1" />
                          {comment.dislikes}
                        </Button>
                        <Button variant="ghost" size="sm" className="h-8 px-2">
                          Reply
                        </Button>
                        <Button variant="ghost" size="sm" className="h-8 px-2">
                          <Flag className="h-3 w-3" />
                        </Button>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </div>

        {/* Sidebar */}
        <div className="lg:col-span-1">
          <div className="sticky top-24 space-y-6">
            {/* Related Articles */}
            {relatedArticles.length > 0 && (
              <Card>
                <CardHeader>
                  <CardTitle>Related Articles</CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  {relatedArticles.map((relatedArticle) => (
                    <ArticleCard 
                      key={relatedArticle.id} 
                      article={relatedArticle} 
                      variant="compact"
                    />
                  ))}
                </CardContent>
              </Card>
            )}

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
        </div>
      </div>
    </div>
  );
};

export default ArticlePage;
