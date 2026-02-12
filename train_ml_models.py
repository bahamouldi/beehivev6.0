#!/usr/bin/env python3
"""
BeeWAF ML Training Script
=========================
Train the advanced ML engine on CSIC 2010 dataset.

Usage:
    python train_ml_models.py --data data/csic_database.csv --save models/ml_engine.pkl
    python train_ml_models.py --data data/csic_database.csv --eval  # Evaluation only
"""

import sys
import os
import argparse
import json
import logging
from datetime import datetime

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from waf.ml_engine import (
    BeeWAFMLEngine, 
    CSICDataLoader, 
    train_from_csic,
    load_engine,
    predict_request
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
log = logging.getLogger('beewaf.training')


def print_banner():
    """Print training banner."""
    print("""
╔══════════════════════════════════════════════════════════════════╗
║         🐝 BeeWAF Advanced ML Training System 🐝                  ║
║                                                                    ║
║  Models: IsolationForest + RandomForest + GradientBoosting        ║
║  Inspired by Cloudflare WAF Attack Score                          ║
╚══════════════════════════════════════════════════════════════════╝
    """)


def print_results(stats: dict):
    """Pretty print training results."""
    if not stats.get('ok'):
        print(f"\n❌ Training failed: {stats.get('error', 'Unknown error')}")
        return
    
    print("\n" + "="*70)
    print("📊 TRAINING RESULTS")
    print("="*70)
    
    print(f"\n📁 Dataset Statistics:")
    print(f"   • Total samples: {stats['samples_total']:,}")
    print(f"   • Training samples: {stats['samples_train']:,}")
    print(f"   • Test samples: {stats['samples_test']:,}")
    print(f"   • Attack ratio: {stats['attack_ratio']*100:.1f}%")
    
    print(f"\n🤖 Model Performance:")
    print("-"*70)
    print(f"{'Model':<25} {'Accuracy':<12} {'Precision':<12} {'Recall':<12} {'F1':<12}")
    print("-"*70)
    
    models = stats['models']
    for model_name, metrics in models.items():
        print(f"{model_name:<25} "
              f"{metrics['accuracy']*100:>6.2f}%     "
              f"{metrics['precision']*100:>6.2f}%     "
              f"{metrics['recall']*100:>6.2f}%     "
              f"{metrics['f1']*100:>6.2f}%")
    
    print("-"*70)
    
    # Highlight ensemble (best model)
    ensemble = models['ensemble']
    print(f"\n🏆 ENSEMBLE PERFORMANCE (Weighted Voting):")
    print(f"   • Accuracy:  {ensemble['accuracy']*100:.2f}%")
    print(f"   • Precision: {ensemble['precision']*100:.2f}%")
    print(f"   • Recall:    {ensemble['recall']*100:.2f}%")
    print(f"   • F1 Score:  {ensemble['f1']*100:.2f}%")
    print(f"   • ROC AUC:   {ensemble['roc_auc']*100:.2f}%")
    
    print(f"\n📈 Top 10 Important Features:")
    for i, (feature, importance) in enumerate(stats['top_features'], 1):
        bar = '█' * int(importance * 50)
        print(f"   {i:2}. {feature:<25} {importance:.4f} {bar}")
    
    print(f"\n🔢 Confusion Matrix:")
    cm = stats['confusion_matrix']
    print(f"                  Predicted")
    print(f"                  Normal  Attack")
    print(f"   Actual Normal  {cm[0][0]:>6}  {cm[0][1]:>6}")
    print(f"   Actual Attack  {cm[1][0]:>6}  {cm[1][1]:>6}")
    
    # Calculate additional metrics
    tn, fp, fn, tp = cm[0][0], cm[0][1], cm[1][0], cm[1][1]
    print(f"\n📋 Classification Details:")
    print(f"   • True Negatives (Normal → Normal):   {tn:,}")
    print(f"   • False Positives (Normal → Attack):  {fp:,}")
    print(f"   • False Negatives (Attack → Normal):  {fn:,}")
    print(f"   • True Positives (Attack → Attack):   {tp:,}")
    
    print("\n" + "="*70)


def test_predictions(model_path: str):
    """Test model with sample payloads."""
    if not load_engine(model_path):
        print("❌ Failed to load model")
        return
    
    print("\n🧪 Testing Model Predictions:")
    print("-"*70)
    
    test_cases = [
        # Normal requests
        {
            'name': 'Normal GET',
            'url': 'http://example.com/products?id=123&category=electronics',
            'body': '',
            'expected': 'normal'
        },
        {
            'name': 'Normal POST',
            'url': 'http://example.com/login',
            'body': 'username=john&password=secret123',
            'expected': 'normal'
        },
        {
            'name': 'Normal search',
            'url': 'http://example.com/search?q=laptop+computer',
            'body': '',
            'expected': 'normal'
        },
        # SQL Injection
        {
            'name': 'SQLi - Classic',
            'url': "http://example.com/user?id=1' OR '1'='1",
            'body': '',
            'expected': 'attack'
        },
        {
            'name': 'SQLi - UNION',
            'url': 'http://example.com/user?id=1 UNION SELECT * FROM users--',
            'body': '',
            'expected': 'attack'
        },
        {
            'name': 'SQLi - Time-based',
            'url': "http://example.com/user?id=1; WAITFOR DELAY '0:0:5'--",
            'body': '',
            'expected': 'attack'
        },
        # XSS
        {
            'name': 'XSS - Script tag',
            'url': 'http://example.com/search?q=<script>alert(1)</script>',
            'body': '',
            'expected': 'attack'
        },
        {
            'name': 'XSS - Event handler',
            'url': 'http://example.com/page?name=<img src=x onerror=alert(1)>',
            'body': '',
            'expected': 'attack'
        },
        # Command Injection
        {
            'name': 'CMDI - Pipe',
            'url': 'http://example.com/ping?host=google.com|cat /etc/passwd',
            'body': '',
            'expected': 'attack'
        },
        {
            'name': 'CMDI - Semicolon',
            'url': 'http://example.com/exec?cmd=ls; rm -rf /',
            'body': '',
            'expected': 'attack'
        },
        # Path Traversal
        {
            'name': 'Path Traversal',
            'url': 'http://example.com/file?path=../../../etc/passwd',
            'body': '',
            'expected': 'attack'
        },
        # SSRF
        {
            'name': 'SSRF - Metadata',
            'url': 'http://example.com/fetch?url=http://169.254.169.254/latest/meta-data',
            'body': '',
            'expected': 'attack'
        },
        # Encoded attacks
        {
            'name': 'Encoded SQLi',
            'url': 'http://example.com/user?id=%27%20OR%20%271%27%3D%271',
            'body': '',
            'expected': 'attack'
        },
    ]
    
    correct = 0
    for test in test_cases:
        result = predict_request(test['url'], test['body'], {})
        predicted = 'attack' if result['is_attack'] else 'normal'
        is_correct = predicted == test['expected']
        correct += is_correct
        
        status = '✅' if is_correct else '❌'
        print(f"   {status} {test['name']:<25} "
              f"Score: {result['attack_score']:.3f} "
              f"→ {predicted:<7} "
              f"(expected: {test['expected']})")
        
        if result.get('attack_type') and result['is_attack']:
            print(f"      └─ Type: {result['attack_type']}")
    
    print("-"*70)
    print(f"   Accuracy: {correct}/{len(test_cases)} ({correct/len(test_cases)*100:.1f}%)")


def main():
    print_banner()
    
    parser = argparse.ArgumentParser(description='Train BeeWAF ML Models')
    parser.add_argument('--data', '-d', 
                       default='data/csic_database.csv',
                       help='Path to CSIC CSV dataset')
    parser.add_argument('--save', '-s',
                       default='models/ml_engine.pkl',
                       help='Path to save trained models')
    parser.add_argument('--eval', '-e', action='store_true',
                       help='Run evaluation tests after training')
    parser.add_argument('--test-only', '-t', action='store_true',
                       help='Only run tests (requires trained model)')
    parser.add_argument('--json', '-j', action='store_true',
                       help='Output results as JSON')
    
    args = parser.parse_args()
    
    if args.test_only:
        test_predictions(args.save)
        return
    
    # Check data file exists
    if not os.path.exists(args.data):
        print(f"❌ Data file not found: {args.data}")
        sys.exit(1)
    
    print(f"📂 Loading data from: {args.data}")
    print(f"💾 Will save model to: {args.save}")
    print()
    
    start_time = datetime.now()
    
    # Train models
    stats = train_from_csic(args.data, args.save)
    
    elapsed = datetime.now() - start_time
    stats['training_time_seconds'] = elapsed.total_seconds()
    
    if args.json:
        print(json.dumps(stats, indent=2, default=str))
    else:
        print_results(stats)
        print(f"\n⏱️  Training completed in {elapsed.total_seconds():.1f} seconds")
        print(f"💾 Models saved to: {args.save}")
    
    # Run evaluation tests
    if args.eval and stats.get('ok'):
        test_predictions(args.save)
    
    print("\n✅ Done!")


if __name__ == '__main__':
    main()
