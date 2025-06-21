import React from 'react';
import { Link } from 'react-router-dom';
import { 
  Target, 
  Users, 
  TrendingUp, 
  Shield, 
  Globe, 
  Mail, 
  Twitter, 
  Linkedin, 
  Github,
  Award,
  Zap,
  Eye,
  Heart
} from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';

const AboutPage: React.FC = () => {
  const teamMembers = [
    {
      name: 'Sarah Mitchell',
      role: 'Editor-in-Chief',
      bio: 'Former Goldman Sachs analyst with 10+ years in traditional finance and 5+ years covering crypto markets.',
      avatar: '/images/avatars/sarah-mitchell.jpg',
      social: {
        twitter: '#',
        linkedin: '#',
      }
    },
    {
      name: 'Marcus Chen',
      role: 'Lead Blockchain Developer',
      bio: 'Ethereum Foundation contributor and expert in DeFi protocols with extensive smart contract auditing experience.',
      avatar: '/images/avatars/marcus-chen.jpg',
      social: {
        twitter: '#',
        github: '#',
      }
    },
    {
      name: 'Elena Rodriguez',
      role: 'DeFi Research Analyst',
      bio: 'PhD in Economics, specializing in decentralized finance protocols and yield farming strategies.',
      avatar: '/images/avatars/elena-rodriguez.jpg',
      social: {
        twitter: '#',
        linkedin: '#',
      }
    },
    {
      name: 'James Thompson',
      role: 'Regulatory Affairs Specialist',
      bio: 'Former SEC attorney with deep expertise in cryptocurrency regulations and compliance.',
      avatar: '/images/avatars/james-thompson.jpg',
      social: {
        twitter: '#',
        linkedin: '#',
      }
    }
  ];

  const stats = [
    {
      icon: Users,
      value: '2.3M+',
      label: 'Monthly Readers',
      description: 'Crypto enthusiasts worldwide'
    },
    {
      icon: TrendingUp,
      value: '10,000+',
      label: 'Articles Published',
      description: 'In-depth analysis and news'
    },
    {
      icon: Globe,
      value: '150+',
      label: 'Countries',
      description: 'Global readership reach'
    },
    {
      icon: Award,
      value: '99.9%',
      label: 'Uptime',
      description: 'Reliable news delivery'
    }
  ];

  const features = [
    {
      icon: Zap,
      title: 'Real-time Market Data',
      description: 'Live cryptocurrency prices, market caps, and trading volumes integrated from trusted APIs.'
    },
    {
      icon: Eye,
      title: 'Expert Analysis',
      description: 'In-depth market analysis from industry experts with proven track records in crypto and traditional finance.'
    },
    {
      icon: Shield,
      title: 'Verified Sources',
      description: 'All news and data verified from multiple reliable sources before publication.'
    },
    {
      icon: Heart,
      title: 'Community Driven',
      description: 'Interactive community features including comments, discussions, and user-generated content.'
    }
  ];

  return (
    <div className="container mx-auto px-4 py-8">
      {/* Hero Section */}
      <div className="text-center mb-16">
        <div className="flex items-center justify-center space-x-3 mb-6">
          <div className="h-12 w-12 rounded-lg bg-gradient-to-br from-blue-600 to-purple-600 flex items-center justify-center text-white font-bold text-lg">
            BC
          </div>
          <h1 className="text-4xl font-bold gradient-text">BlockchainNews</h1>
        </div>
        
        <h2 className="text-3xl md:text-4xl font-bold mb-6 max-w-4xl mx-auto leading-tight">
          Your Trusted Source for Blockchain and Cryptocurrency News
        </h2>
        
        <p className="text-xl text-muted-foreground mb-8 max-w-3xl mx-auto leading-relaxed">
          We deliver accurate, timely, and comprehensive coverage of the blockchain ecosystem, 
          from market analysis to technological breakthroughs, regulatory developments, and industry insights.
        </p>
        
        <div className="flex flex-col sm:flex-row gap-4 justify-center">
          <Button size="lg" asChild>
            <Link to="/">Explore Articles</Link>
          </Button>
          <Button size="lg" variant="outline" asChild>
            <Link to="/market-data">View Market Data</Link>
          </Button>
        </div>
      </div>

      {/* Stats Section */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-16">
        {stats.map((stat, index) => (
          <Card key={index} className="text-center">
            <CardContent className="p-6">
              <stat.icon className="h-8 w-8 mx-auto mb-4 text-primary" />
              <div className="text-3xl font-bold mb-2">{stat.value}</div>
              <div className="font-semibold mb-1">{stat.label}</div>
              <div className="text-sm text-muted-foreground">{stat.description}</div>
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Mission Section */}
      <Card className="mb-16">
        <CardHeader className="text-center">
          <Target className="h-12 w-12 mx-auto mb-4 text-primary" />
          <CardTitle className="text-3xl">Our Mission</CardTitle>
        </CardHeader>
        <CardContent className="max-w-4xl mx-auto">
          <p className="text-lg text-muted-foreground leading-relaxed text-center mb-8">
            To democratize access to high-quality blockchain and cryptocurrency information, 
            empowering our readers to make informed decisions in the rapidly evolving digital asset landscape.
          </p>
          
          <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
            <div>
              <h3 className="text-xl font-semibold mb-3">What We Stand For</h3>
              <ul className="space-y-2 text-muted-foreground">
                <li className="flex items-start space-x-2">
                  <span className="w-2 h-2 bg-primary rounded-full mt-2 flex-shrink-0"></span>
                  <span>Unbiased, fact-based reporting</span>
                </li>
                <li className="flex items-start space-x-2">
                  <span className="w-2 h-2 bg-primary rounded-full mt-2 flex-shrink-0"></span>
                  <span>Educational content for all experience levels</span>
                </li>
                <li className="flex items-start space-x-2">
                  <span className="w-2 h-2 bg-primary rounded-full mt-2 flex-shrink-0"></span>
                  <span>Transparency in sources and methodology</span>
                </li>
                <li className="flex items-start space-x-2">
                  <span className="w-2 h-2 bg-primary rounded-full mt-2 flex-shrink-0"></span>
                  <span>Community-driven discussions and insights</span>
                </li>
              </ul>
            </div>
            
            <div>
              <h3 className="text-xl font-semibold mb-3">Our Commitment</h3>
              <ul className="space-y-2 text-muted-foreground">
                <li className="flex items-start space-x-2">
                  <span className="w-2 h-2 bg-primary rounded-full mt-2 flex-shrink-0"></span>
                  <span>24/7 coverage of breaking developments</span>
                </li>
                <li className="flex items-start space-x-2">
                  <span className="w-2 h-2 bg-primary rounded-full mt-2 flex-shrink-0"></span>
                  <span>Real-time market data and analysis</span>
                </li>
                <li className="flex items-start space-x-2">
                  <span className="w-2 h-2 bg-primary rounded-full mt-2 flex-shrink-0"></span>
                  <span>Expert insights from industry leaders</span>
                </li>
                <li className="flex items-start space-x-2">
                  <span className="w-2 h-2 bg-primary rounded-full mt-2 flex-shrink-0"></span>
                  <span>Accessible content for all audiences</span>
                </li>
              </ul>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Features Section */}
      <div className="mb-16">
        <h2 className="text-3xl font-bold text-center mb-12">Why Choose BlockchainNews</h2>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
          {features.map((feature, index) => (
            <Card key={index}>
              <CardContent className="p-6">
                <feature.icon className="h-10 w-10 text-primary mb-4" />
                <h3 className="text-xl font-semibold mb-3">{feature.title}</h3>
                <p className="text-muted-foreground leading-relaxed">{feature.description}</p>
              </CardContent>
            </Card>
          ))}
        </div>
      </div>

      {/* Team Section */}
      <div className="mb-16">
        <h2 className="text-3xl font-bold text-center mb-12">Meet Our Team</h2>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-8">
          {teamMembers.map((member, index) => (
            <Card key={index}>
              <CardContent className="p-6 text-center">
                <img
                  src={member.avatar}
                  alt={member.name}
                  className="w-20 h-20 rounded-full mx-auto mb-4 object-cover"
                  onError={(e) => {
                    e.currentTarget.src = '/images/avatars/default.jpg';
                  }}
                />
                <h3 className="text-lg font-semibold mb-1">{member.name}</h3>
                <Badge variant="outline" className="mb-3">{member.role}</Badge>
                <p className="text-sm text-muted-foreground mb-4 leading-relaxed">
                  {member.bio}
                </p>
                <div className="flex justify-center space-x-2">
                  {member.social.twitter && (
                    <Button variant="ghost" size="sm">
                      <Twitter className="h-4 w-4" />
                    </Button>
                  )}
                  {member.social.linkedin && (
                    <Button variant="ghost" size="sm">
                      <Linkedin className="h-4 w-4" />
                    </Button>
                  )}
                  {member.social.github && (
                    <Button variant="ghost" size="sm">
                      <Github className="h-4 w-4" />
                    </Button>
                  )}
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      </div>

      {/* Coverage Areas */}
      <Card className="mb-16">
        <CardHeader>
          <CardTitle className="text-3xl text-center">Our Coverage</CardTitle>
          <p className="text-muted-foreground text-center">
            Comprehensive blockchain and cryptocurrency ecosystem coverage
          </p>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            <div className="text-center p-4">
              <div className="w-12 h-12 bg-green-100 dark:bg-green-900 rounded-lg flex items-center justify-center mx-auto mb-3">
                <TrendingUp className="h-6 w-6 text-green-600 dark:text-green-400" />
              </div>
              <h3 className="font-semibold mb-2">Market Analysis</h3>
              <p className="text-sm text-muted-foreground">
                Technical analysis, price predictions, and market trends
              </p>
            </div>
            
            <div className="text-center p-4">
              <div className="w-12 h-12 bg-purple-100 dark:bg-purple-900 rounded-lg flex items-center justify-center mx-auto mb-3">
                <Zap className="h-6 w-6 text-purple-600 dark:text-purple-400" />
              </div>
              <h3 className="font-semibold mb-2">DeFi Protocols</h3>
              <p className="text-sm text-muted-foreground">
                Decentralized finance innovations and yield farming
              </p>
            </div>
            
            <div className="text-center p-4">
              <div className="w-12 h-12 bg-orange-100 dark:bg-orange-900 rounded-lg flex items-center justify-center mx-auto mb-3">
                <Award className="h-6 w-6 text-orange-600 dark:text-orange-400" />
              </div>
              <h3 className="font-semibold mb-2">NFTs & Digital Art</h3>
              <p className="text-sm text-muted-foreground">
                Non-fungible tokens, digital collectibles, and marketplaces
              </p>
            </div>
            
            <div className="text-center p-4">
              <div className="w-12 h-12 bg-red-100 dark:bg-red-900 rounded-lg flex items-center justify-center mx-auto mb-3">
                <Shield className="h-6 w-6 text-red-600 dark:text-red-400" />
              </div>
              <h3 className="font-semibold mb-2">Regulations</h3>
              <p className="text-sm text-muted-foreground">
                Government policies, compliance, and legal developments
              </p>
            </div>
            
            <div className="text-center p-4">
              <div className="w-12 h-12 bg-blue-100 dark:bg-blue-900 rounded-lg flex items-center justify-center mx-auto mb-3">
                <Globe className="h-6 w-6 text-blue-600 dark:text-blue-400" />
              </div>
              <h3 className="font-semibold mb-2">Technology Updates</h3>
              <p className="text-sm text-muted-foreground">
                Blockchain innovations, protocol upgrades, and tech news
              </p>
            </div>
            
            <div className="text-center p-4">
              <div className="w-12 h-12 bg-gray-100 dark:bg-gray-900 rounded-lg flex items-center justify-center mx-auto mb-3">
                <Users className="h-6 w-6 text-gray-600 dark:text-gray-400" />
              </div>
              <h3 className="font-semibold mb-2">Institutional Adoption</h3>
              <p className="text-sm text-muted-foreground">
                Corporate adoption, institutional investments, and partnerships
              </p>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Contact Section */}
      <Card>
        <CardHeader>
          <CardTitle className="text-3xl text-center">Get In Touch</CardTitle>
          <p className="text-muted-foreground text-center">
            Have a story tip, partnership inquiry, or just want to say hello?
          </p>
        </CardHeader>
        <CardContent className="text-center">
          <div className="flex flex-col sm:flex-row gap-4 justify-center mb-8">
            <Button className="flex items-center gap-2">
              <Mail className="h-4 w-4" />
              contact@blockchainnews.com
            </Button>
            <Button variant="outline" className="flex items-center gap-2">
              <Twitter className="h-4 w-4" />
              Follow Us
            </Button>
          </div>
          
          <p className="text-sm text-muted-foreground max-w-2xl mx-auto">
            For press inquiries, partnership opportunities, or editorial submissions, 
            please reach out to us. We're always looking for expert contributors and 
            industry insights to share with our community.
          </p>
        </CardContent>
      </Card>
    </div>
  );
};

export default AboutPage;
