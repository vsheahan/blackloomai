#!/usr/bin/env python3
"""
BlackLoom Research Laboratory Demo
Demonstrates the capabilities of the AI security research platform
"""

import asyncio
import sys
from pathlib import Path

# Add the parent directory to the path so we can import our modules
sys.path.insert(0, str(Path(__file__).parent.parent))

from blackloom_research.core import ResearchLab, ResearchLabConfig
from blackloom_research.discovery import VulnerabilityScanExperiment, ScanTarget, VulnerabilityType


def print_banner():
    """Print the BlackLoom Research banner"""
    banner = """
╔══════════════════════════════════════════════════════════════╗
║                    BlackLoom Research                        ║
║                AI Security Research Laboratory               ║
║          Advancing AI Security Through Research             ║
╚══════════════════════════════════════════════════════════════╝
"""
    print(banner)


def print_section(title: str):
    """Print a section header"""
    print(f"\n{'='*60}")
    print(f" {title}")
    print('='*60)


async def demo_lab_initialization():
    """Demonstrate research lab initialization"""
    print_section("RESEARCH LAB INITIALIZATION")
    
    # Configure research lab
    config = ResearchLabConfig(
        lab_name="BlackLoom Demo Research Lab",
        compute_nodes=2,
        max_concurrent_experiments=3,
        data_storage_path=Path("./research_demo_data"),
        enable_distributed_computing=False,  # Simplified for demo
        enable_gpu_acceleration=False,       # Simplified for demo
        ethics_review_required=True
    )
    
    print(f"🔬 Initializing {config.lab_name}...")
    print(f"📊 Compute nodes: {config.compute_nodes}")
    print(f"🧪 Max concurrent experiments: {config.max_concurrent_experiments}")
    print(f"💾 Data storage: {config.data_storage_path}")
    
    async with ResearchLab(config) as lab:
        print("✅ Research lab initialized successfully!")
        
        # Display lab metrics
        metrics = lab.get_lab_metrics()
        print(f"📈 Lab Status:")
        print(f"   • Running experiments: {metrics.experiments_running}")
        print(f"   • Queued experiments: {metrics.experiments_queued}")
        print(f"   • CPU utilization: {metrics.cpu_utilization:.1f}%")
        print(f"   • Memory utilization: {metrics.memory_utilization:.1f}%")
        
        return lab


async def demo_vulnerability_scanning():
    """Demonstrate vulnerability scanning capabilities"""
    print_section("VULNERABILITY SCANNING DEMONSTRATION")
    
    # Create demo scan targets
    scan_targets = [
        ScanTarget(
            model_id="demo_model_1",
            model_name="Demo Text Generation Model",
            model_type="text_generation",
            endpoint_url="http://localhost:8000/api/generate",
            metadata={"version": "1.0", "provider": "demo"}
        ),
        ScanTarget(
            model_id="demo_model_2", 
            model_name="Demo Chat Model",
            model_type="chat",
            endpoint_url="http://localhost:8001/api/chat",
            metadata={"version": "2.1", "provider": "demo"}
        )
    ]
    
    # Define vulnerability types to test
    vuln_types = [
        VulnerabilityType.PROMPT_INJECTION,
        VulnerabilityType.ADVERSARIAL_INPUT,
        VulnerabilityType.PRIVACY_LEAK
    ]
    
    print(f"🎯 Creating vulnerability scan experiment...")
    print(f"   • Targets: {len(scan_targets)}")
    print(f"   • Vulnerability types: {[vt.value for vt in vuln_types]}")
    
    # Create vulnerability scan experiment
    vuln_experiment = VulnerabilityScanExperiment(
        targets=scan_targets,
        vulnerability_types=vuln_types
    )
    
    print(f"🧪 Experiment created: {vuln_experiment.id}")
    print(f"   • Name: {vuln_experiment.metadata.name}")
    print(f"   • Type: {vuln_experiment.metadata.experiment_type.value}")
    print(f"   • Estimated runtime: {vuln_experiment.metadata.estimated_runtime_hours} hours")
    print(f"   • Safety measures: {vuln_experiment.metadata.safety_measures}")
    
    return vuln_experiment


async def demo_experiment_execution():
    """Demonstrate experiment execution"""
    print_section("EXPERIMENT EXECUTION")
    
    config = ResearchLabConfig(
        lab_name="BlackLoom Demo Lab",
        compute_nodes=1,
        max_concurrent_experiments=1,
        data_storage_path=Path("./research_demo_data"),
        enable_distributed_computing=False,
        enable_gpu_acceleration=False,
        ethics_review_required=True
    )
    
    async with ResearchLab(config) as lab:
        # Create vulnerability scan experiment
        scan_targets = [
            ScanTarget(
                model_id="test_model",
                model_name="Test AI Model",
                model_type="text_generation"
            )
        ]
        
        experiment = VulnerabilityScanExperiment(
            targets=scan_targets,
            vulnerability_types=[VulnerabilityType.PROMPT_INJECTION]
        )
        
        print(f"🚀 Submitting experiment to lab...")
        experiment_id = await lab.submit_experiment(experiment)
        print(f"✅ Experiment submitted: {experiment_id}")
        
        # Monitor experiment progress
        print("⏳ Monitoring experiment progress...")
        
        while True:
            status = await lab.get_experiment_status(experiment_id)
            print(f"   Status: {status.get('runtime_status', {}).get('status', 'unknown')}")
            
            if status.get('runtime_status', {}).get('status') in ['completed', 'failed', 'cancelled']:
                break
                
            await asyncio.sleep(1)
        
        # Get final results
        final_status = await lab.get_experiment_status(experiment_id)
        if 'result' in final_status:
            result = final_status['result']
            print(f"🎉 Experiment completed!")
            print(f"   • Duration: {result.get('duration_seconds', 0):.1f} seconds")
            print(f"   • Success: {result.get('success', False)}")
            print(f"   • Discoveries: {len(result.get('discoveries', []))}")
            print(f"   • Artifacts: {len(result.get('artifacts', []))}")
            
            # Display discoveries
            discoveries = result.get('discoveries', [])
            if discoveries:
                print(f"🔍 Research Discoveries:")
                for i, discovery in enumerate(discoveries[:3], 1):  # Show first 3
                    print(f"   {i}. {discovery.get('type', 'unknown')}: {discovery.get('title', 'N/A')}")
                    if len(discoveries) > 3:
                        print(f"   ... and {len(discoveries) - 3} more")
        
        return final_status


async def demo_lab_metrics():
    """Demonstrate lab metrics and monitoring"""
    print_section("LAB METRICS AND MONITORING")
    
    config = ResearchLabConfig(
        lab_name="BlackLoom Metrics Demo",
        compute_nodes=4,
        max_concurrent_experiments=5,
        data_storage_path=Path("./metrics_demo_data")
    )
    
    async with ResearchLab(config) as lab:
        metrics = lab.get_lab_metrics()
        
        print("📊 Current Lab Metrics:")
        print(f"   • Experiments completed: {metrics.experiments_completed}")
        print(f"   • Experiments running: {metrics.experiments_running}")
        print(f"   • Experiments queued: {metrics.experiments_queued}")
        print(f"   • CPU utilization: {metrics.cpu_utilization:.1f}%")
        print(f"   • GPU utilization: {metrics.gpu_utilization:.1f}%")
        print(f"   • Memory utilization: {metrics.memory_utilization:.1f}%")
        print(f"   • Storage used: {metrics.storage_used_gb:.1f} GB")
        print(f"   • Threats discovered: {metrics.threats_discovered}")
        print(f"   • Defenses developed: {metrics.defenses_developed}")
        print(f"   • Papers published: {metrics.papers_published}")
        print(f"   • Vulnerabilities disclosed: {metrics.vulnerabilities_disclosed}")
        
        print("\n🔧 Lab Configuration:")
        print(f"   • Lab name: {lab.config.lab_name}")
        print(f"   • Compute nodes: {lab.config.compute_nodes}")
        print(f"   • Security isolation: {lab.config.security_isolation_level}")
        print(f"   • Ethics review: {lab.config.ethics_review_required}")
        print(f"   • Auto backup interval: {lab.config.auto_backup_interval_hours}h")


async def demo_research_areas():
    """Demonstrate different research areas"""
    print_section("RESEARCH AREAS OVERVIEW")
    
    research_areas = [
        {
            "name": "🔍 Threat Discovery",
            "description": "Automated vulnerability discovery and novel attack vector generation",
            "capabilities": [
                "AI model fuzzing and testing",
                "Zero-day threat detection", 
                "Adversarial attack generation",
                "Security weakness identification"
            ]
        },
        {
            "name": "🧠 Threat Intelligence",
            "description": "Real-time threat monitoring and intelligence gathering",
            "capabilities": [
                "Academic research analysis",
                "Social media threat intelligence",
                "Attack attribution and tracking",
                "Threat trend prediction"
            ]
        },
        {
            "name": "🔄 Adaptive Defenses", 
            "description": "Self-evolving security systems and defense optimization",
            "capabilities": [
                "Meta-learning for defense",
                "Dynamic rule generation",
                "Automated response learning",
                "Defense effectiveness optimization"
            ]
        },
        {
            "name": "🎭 Multimodal Security",
            "description": "Cross-modal attack research and media forensics",
            "capabilities": [
                "Cross-modal vulnerability research",
                "Steganography and hidden attacks",
                "Deepfake detection research",
                "Media manipulation forensics"
            ]
        },
        {
            "name": "👥 Human-AI Security",
            "description": "Human-AI interaction security and social engineering research",
            "capabilities": [
                "AI-powered social engineering research",
                "Trust calibration studies",
                "Cognitive security analysis",
                "Human-in-the-loop vulnerabilities"
            ]
        }
    ]
    
    for area in research_areas:
        print(f"\n{area['name']}")
        print(f"   Description: {area['description']}")
        print("   Capabilities:")
        for capability in area['capabilities']:
            print(f"     • {capability}")


async def demo_safety_and_ethics():
    """Demonstrate safety and ethics framework"""
    print_section("SAFETY AND ETHICS FRAMEWORK")
    
    print("🛡️ Safety Measures:")
    safety_measures = [
        "Sandboxed experiment execution",
        "Network isolation for dangerous experiments", 
        "Automated attack containment",
        "Resource usage monitoring and limits",
        "Emergency shutdown capabilities",
        "Audit logging of all activities"
    ]
    
    for measure in safety_measures:
        print(f"   • {measure}")
    
    print("\n⚖️ Ethics Guidelines:")
    ethics_guidelines = [
        "Mandatory ethics review for sensitive research",
        "Responsible disclosure of vulnerabilities",
        "Harm minimization in experiment design",
        "Privacy protection for research data",
        "Dual-use research oversight",
        "Community benefit prioritization"
    ]
    
    for guideline in ethics_guidelines:
        print(f"   • {guideline}")
    
    print("\n🔒 Security Isolation:")
    isolation_features = [
        "High-security isolation level by default",
        "Container-based experiment isolation",
        "Filesystem and network restrictions",
        "Resource quotas and limits",
        "Attack propagation prevention",
        "Secure artifact storage"
    ]
    
    for feature in isolation_features:
        print(f"   • {feature}")


async def main():
    """Main demo function"""
    print_banner()
    print("Welcome to the BlackLoom Research Laboratory demonstration!")
    print("This demo showcases our AI security research platform capabilities.")
    
    try:
        # Demo 1: Lab initialization
        await demo_lab_initialization()
        
        # Demo 2: Research areas overview
        await demo_research_areas()
        
        # Demo 3: Vulnerability scanning
        await demo_vulnerability_scanning()
        
        # Demo 4: Experiment execution
        await demo_experiment_execution()
        
        # Demo 5: Lab metrics
        await demo_lab_metrics()
        
        # Demo 6: Safety and ethics
        await demo_safety_and_ethics()
        
        print_section("DEMO COMPLETE")
        print("✅ All demonstrations completed successfully!")
        print("🔬 BlackLoom Research is ready to advance AI security.")
        print("\n🚀 Next Steps:")
        print("   • Explore the research modules in blackloom_research/")
        print("   • Run real experiments with actual AI models") 
        print("   • Contribute to the AI security research community")
        print("   • Develop novel threat detection methods")
        print("   • Build adaptive defense systems")
        
    except Exception as e:
        print(f"\n❌ Demo failed with error: {str(e)}")
        print("Please check the installation and configuration.")
        return 1
    
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))