import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import { 
  Twitter, 
  Github, 
  Linkedin, 
  Mail, 
  Send,
  Bitcoin,
  Shield,
  FileText 
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { toast } from 'sonner';

const Footer: React.FC = () => {
  const [email, setEmail] = useState('');
  const [isSubscribing, setIsSubscribing] = useState(false);

  const handleNewsletterSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!email) return;

    setIsSubscribing(true);
    
    // Simulate newsletter subscription
    await new Promise(resolve => setTimeout(resolve, 1000));
    
    toast.success('Successfully subscribed to our newsletter!');
    setEmail('');
    setIsSubscribing(false);
  };

  const currentYear = new Date().getFullYear();

  return (
    <footer className="bg-muted/50 border-t mt-auto">
      <div className="container mx-auto px-4 py-12">
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-8">
          {/* Company Info */}
          <div className="space-y-4">
            <div className="flex items-center space-x-2">
              <div className="h-8 w-8 rounded-lg bg-gradient-to-br from-blue-600 to-purple-600 flex items-center justify-center text-white font-bold text-sm">
                BC
              </div>
              <span className="font-bold text-lg gradient-text">
                BlockchainNews
              </span>
            </div>
            <p className="text-sm text-muted-foreground">
              Your trusted source for the latest blockchain and cryptocurrency news, 
              market analysis, and technology insights.
            </p>
            <div className="flex space-x-4">
              <Button variant="ghost" size="sm" asChild>
                <a href="https://twitter.com" target="_blank" rel="noopener noreferrer">
                  <Twitter className="h-4 w-4" />
                </a>
              </Button>
              <Button variant="ghost" size="sm" asChild>
                <a href="https://github.com" target="_blank" rel="noopener noreferrer">
                  <Github className="h-4 w-4" />
                </a>
              </Button>
              <Button variant="ghost" size="sm" asChild>
                <a href="https://linkedin.com" target="_blank" rel="noopener noreferrer">
                  <Linkedin className="h-4 w-4" />
                </a>
              </Button>
              <Button variant="ghost" size="sm" asChild>
                <a href="mailto:contact@blockchainnews.com">
                  <Mail className="h-4 w-4" />
                </a>
              </Button>
            </div>
          </div>

          {/* Categories */}
          <div className="space-y-4">
            <h3 className="font-semibold text-sm uppercase tracking-wider">Categories</h3>
            <div className="space-y-2">
              <Link 
                to="/category/market-analysis" 
                className="block text-sm text-muted-foreground hover:text-foreground transition-colors"
              >
                Market Analysis
              </Link>
              <Link 
                to="/category/defi" 
                className="block text-sm text-muted-foreground hover:text-foreground transition-colors"
              >
                DeFi
              </Link>
              <Link 
                to="/category/nfts" 
                className="block text-sm text-muted-foreground hover:text-foreground transition-colors"
              >
                NFTs
              </Link>
              <Link 
                to="/category/regulations" 
                className="block text-sm text-muted-foreground hover:text-foreground transition-colors"
              >
                Regulations
              </Link>
              <Link 
                to="/category/technology-updates" 
                className="block text-sm text-muted-foreground hover:text-foreground transition-colors"
              >
                Technology Updates
              </Link>
            </div>
          </div>

          {/* Resources */}
          <div className="space-y-4">
            <h3 className="font-semibold text-sm uppercase tracking-wider">Resources</h3>
            <div className="space-y-2">
              <Link 
                to="/market-data" 
                className="block text-sm text-muted-foreground hover:text-foreground transition-colors"
              >
                Market Data
              </Link>
              <Link 
                to="/about" 
                className="block text-sm text-muted-foreground hover:text-foreground transition-colors"
              >
                About Us
              </Link>
              <a 
                href="#" 
                className="block text-sm text-muted-foreground hover:text-foreground transition-colors"
              >
                Contact
              </a>
              <a 
                href="#" 
                className="block text-sm text-muted-foreground hover:text-foreground transition-colors"
              >
                Advertise
              </a>
              <a 
                href="#" 
                className="block text-sm text-muted-foreground hover:text-foreground transition-colors"
              >
                API
              </a>
            </div>
          </div>

          {/* Newsletter */}
          <div className="space-y-4">
            <h3 className="font-semibold text-sm uppercase tracking-wider">Newsletter</h3>
            <p className="text-sm text-muted-foreground">
              Get the latest crypto news and market insights delivered to your inbox.
            </p>
            <form onSubmit={handleNewsletterSubmit} className="space-y-2">
              <Input
                type="email"
                placeholder="Enter your email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                required
              />
              <Button 
                type="submit" 
                className="w-full" 
                disabled={isSubscribing}
              >
                {isSubscribing ? (
                  'Subscribing...'
                ) : (
                  <>
                    <Send className="h-4 w-4 mr-2" />
                    Subscribe
                  </>
                )}
              </Button>
            </form>
          </div>
        </div>

        {/* Bottom Section */}
        <div className="border-t pt-8 mt-8">
          <div className="flex flex-col md:flex-row justify-between items-center space-y-4 md:space-y-0">
            <div className="flex items-center space-x-4 text-sm text-muted-foreground">
              <span>© {currentYear} BlockchainNews. All rights reserved.</span>
            </div>
            
            <div className="flex items-center space-x-6 text-sm">
              <a 
                href="#" 
                className="text-muted-foreground hover:text-foreground transition-colors flex items-center space-x-1"
              >
                <FileText className="h-4 w-4" />
                <span>Privacy Policy</span>
              </a>
              <a 
                href="#" 
                className="text-muted-foreground hover:text-foreground transition-colors flex items-center space-x-1"
              >
                <Shield className="h-4 w-4" />
                <span>Terms of Service</span>
              </a>
              <div className="flex items-center space-x-1 text-muted-foreground">
                <Bitcoin className="h-4 w-4" />
                <span>Crypto Focused</span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </footer>
  );
};

export default Footer;
