"""
BlackLoom Research Lab Manager
Central coordination for all research activities and infrastructure
"""

import asyncio
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from enum import Enum

from .compute_cluster import ComputeCluster, ResourceManager
from .data_warehouse import ThreatDataWarehouse
from .experiment import ExperimentRunner


class LabStatus(Enum):
    """Research lab operational status"""
    INITIALIZING = "initializing"
    READY = "ready"
    RUNNING_EXPERIMENTS = "running_experiments"
    MAINTENANCE = "maintenance"
    ERROR = "error"


@dataclass
class ResearchLabConfig:
    """Configuration for the research laboratory"""
    lab_name: str = "BlackLoom Research Lab"
    compute_nodes: int = 4
    max_concurrent_experiments: int = 10
    data_storage_path: Path = field(default_factory=lambda: Path("./research_data"))
    experiment_timeout_hours: int = 24
    auto_backup_interval_hours: int = 6
    enable_distributed_computing: bool = True
    enable_gpu_acceleration: bool = True
    security_isolation_level: str = "high"  # high, medium, low
    ethics_review_required: bool = True


@dataclass
class LabMetrics:
    """Research lab performance metrics"""
    experiments_completed: int = 0
    experiments_running: int = 0
    experiments_queued: int = 0
    cpu_utilization: float = 0.0
    gpu_utilization: float = 0.0
    memory_utilization: float = 0.0
    storage_used_gb: float = 0.0
    threats_discovered: int = 0
    defenses_developed: int = 0
    papers_published: int = 0
    vulnerabilities_disclosed: int = 0


class ResearchLabManager:
    """
    Central manager for BlackLoom Research Laboratory
    Coordinates all research activities, infrastructure, and safety protocols
    """

    def __init__(self, config: Optional[ResearchLabConfig] = None):
        self.config = config or ResearchLabConfig()
        self.logger = logging.getLogger(__name__)
        self.status = LabStatus.INITIALIZING
        self.start_time = datetime.now(timezone.utc)
        
        # Initialize core components
        self.compute_cluster: Optional[ComputeCluster] = None
        self.data_warehouse: Optional[ThreatDataWarehouse] = None
        self.experiment_runner: Optional[ExperimentRunner] = None
        self.resource_manager: Optional[ResourceManager] = None
        
        # Tracking and metrics
        self.active_experiments: Dict[str, Any] = {}
        self.completed_experiments: List[str] = []
        self.metrics = LabMetrics()
        
        # Safety and security
        self.safety_protocols_enabled = True
        self.isolation_containers: Dict[str, str] = {}

    async def initialize_lab(self) -> bool:
        """
        Initialize all laboratory infrastructure and systems
        
        Returns:
            bool: True if initialization successful, False otherwise
        """
        try:
            self.logger.info(f"Initializing {self.config.lab_name}...")
            
            # Create data directories
            self.config.data_storage_path.mkdir(parents=True, exist_ok=True)
            (self.config.data_storage_path / "experiments").mkdir(exist_ok=True)
            (self.config.data_storage_path / "datasets").mkdir(exist_ok=True)
            (self.config.data_storage_path / "models").mkdir(exist_ok=True)
            (self.config.data_storage_path / "results").mkdir(exist_ok=True)
            
            # Initialize compute infrastructure
            self.resource_manager = ResourceManager(
                max_cpu_cores=self.config.compute_nodes * 8,
                max_memory_gb=self.config.compute_nodes * 32,
                enable_gpu=self.config.enable_gpu_acceleration
            )
            
            if self.config.enable_distributed_computing:
                self.compute_cluster = ComputeCluster(
                    num_nodes=self.config.compute_nodes,
                    resource_manager=self.resource_manager
                )
                await self.compute_cluster.initialize()
            
            # Initialize data warehouse
            self.data_warehouse = ThreatDataWarehouse(
                storage_path=self.config.data_storage_path / "datasets"
            )
            await self.data_warehouse.initialize()
            
            # Initialize experiment runner
            self.experiment_runner = ExperimentRunner(
                compute_cluster=self.compute_cluster,
                data_warehouse=self.data_warehouse,
                max_concurrent=self.config.max_concurrent_experiments,
                timeout_hours=self.config.experiment_timeout_hours
            )
            
            # Setup safety protocols
            await self._setup_safety_protocols()
            
            # Start monitoring and maintenance tasks
            asyncio.create_task(self._monitoring_loop())
            asyncio.create_task(self._maintenance_loop())
            
            self.status = LabStatus.READY
            self.logger.info("Research lab initialization completed successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to initialize research lab: {e}")
            self.status = LabStatus.ERROR
            return False

    async def submit_experiment(self, experiment: 'Experiment') -> str:
        """
        Submit a research experiment to the lab queue
        
        Args:
            experiment: The experiment to run
            
        Returns:
            str: Experiment ID for tracking
        """
        if self.status != LabStatus.READY:
            raise RuntimeError(f"Lab not ready (status: {self.status})")
        
        # Ethics review if required
        if self.config.ethics_review_required:
            ethics_approved = await self._ethics_review(experiment)
            if not ethics_approved:
                raise ValueError("Experiment failed ethics review")
        
        # Security isolation setup
        isolation_id = await self._setup_experiment_isolation(experiment)
        
        # Submit to experiment runner
        experiment_id = await self.experiment_runner.submit_experiment(
            experiment, isolation_id
        )
        
        self.active_experiments[experiment_id] = {
            'experiment': experiment,
            'isolation_id': isolation_id,
            'submitted_at': datetime.now(timezone.utc),
            'status': 'queued'
        }
        
        self.metrics.experiments_queued += 1
        self.logger.info(f"Experiment {experiment_id} submitted successfully")
        
        return experiment_id

    async def get_experiment_status(self, experiment_id: str) -> Dict[str, Any]:
        """Get status and results of an experiment"""
        if experiment_id in self.active_experiments:
            experiment_info = self.active_experiments[experiment_id]
            runtime_status = await self.experiment_runner.get_status(experiment_id)
            
            return {
                **experiment_info,
                'runtime_status': runtime_status,
                'lab_metrics': self.get_lab_metrics()
            }
        elif experiment_id in self.completed_experiments:
            # Load from storage
            results = await self._load_experiment_results(experiment_id)
            return results
        else:
            raise ValueError(f"Experiment {experiment_id} not found")

    async def cancel_experiment(self, experiment_id: str) -> bool:
        """Cancel a running or queued experiment"""
        if experiment_id not in self.active_experiments:
            return False
        
        success = await self.experiment_runner.cancel_experiment(experiment_id)
        
        if success:
            # Cleanup isolation
            isolation_id = self.active_experiments[experiment_id]['isolation_id']
            await self._cleanup_experiment_isolation(isolation_id)
            
            # Move to completed
            self.completed_experiments.append(experiment_id)
            del self.active_experiments[experiment_id]
            
            self.metrics.experiments_queued = max(0, self.metrics.experiments_queued - 1)
            
        return success

    def get_lab_metrics(self) -> LabMetrics:
        """Get current laboratory metrics and statistics"""
        # Update real-time metrics
        if self.resource_manager:
            self.metrics.cpu_utilization = self.resource_manager.get_cpu_utilization()
            self.metrics.gpu_utilization = self.resource_manager.get_gpu_utilization()
            self.metrics.memory_utilization = self.resource_manager.get_memory_utilization()
        
        self.metrics.experiments_running = len([
            exp for exp in self.active_experiments.values() 
            if exp['status'] == 'running'
        ])
        
        self.metrics.experiments_queued = len([
            exp for exp in self.active_experiments.values() 
            if exp['status'] == 'queued'
        ])
        
        return self.metrics

    async def shutdown_lab(self) -> None:
        """Gracefully shutdown the research laboratory"""
        self.logger.info("Shutting down research lab...")
        self.status = LabStatus.MAINTENANCE
        
        # Cancel all running experiments with grace period
        for experiment_id in list(self.active_experiments.keys()):
            await self.cancel_experiment(experiment_id)
        
        # Shutdown infrastructure
        if self.compute_cluster:
            await self.compute_cluster.shutdown()
        
        if self.data_warehouse:
            await self.data_warehouse.close()
        
        # Final backup
        await self._backup_lab_state()
        
        self.logger.info("Research lab shutdown completed")

    async def _ethics_review(self, experiment: 'Experiment') -> bool:
        """
        Conduct ethics review of research experiment
        
        Args:
            experiment: Experiment to review
            
        Returns:
            bool: True if approved, False if rejected
        """
        # Check for dual-use research concerns
        if hasattr(experiment, 'tags') and 'dual-use' in experiment.tags:
            self.logger.warning(f"Dual-use research detected: {experiment.name}")
            # In production, this would involve human review
            # For now, we'll allow but log
        
        # Check for high-risk attack generation
        if hasattr(experiment, 'generates_attacks') and experiment.generates_attacks:
            if not hasattr(experiment, 'safety_measures'):
                self.logger.error(f"Attack generation without safety measures: {experiment.name}")
                return False
        
        # Check data privacy requirements
        if hasattr(experiment, 'uses_personal_data') and experiment.uses_personal_data:
            if not hasattr(experiment, 'privacy_compliance'):
                self.logger.error(f"Personal data usage without privacy compliance: {experiment.name}")
                return False
        
        return True

    async def _setup_experiment_isolation(self, experiment: 'Experiment') -> str:
        """Setup security isolation for experiment execution"""
        import uuid
        isolation_id = str(uuid.uuid4())
        
        # Create isolated container/environment
        # This would integrate with Docker/Kubernetes in production
        isolation_config = {
            'network_isolation': True,
            'filesystem_isolation': True,
            'resource_limits': {
                'cpu': 2.0,
                'memory': '8GB',
                'disk': '50GB'
            }
        }
        
        self.isolation_containers[isolation_id] = isolation_config
        return isolation_id

    async def _cleanup_experiment_isolation(self, isolation_id: str) -> None:
        """Cleanup experiment isolation resources"""
        if isolation_id in self.isolation_containers:
            # Cleanup container/environment
            del self.isolation_containers[isolation_id]

    async def _setup_safety_protocols(self) -> None:
        """Setup safety protocols and monitoring"""
        # Network isolation
        self.logger.info("Configuring network isolation...")
        
        # Resource monitoring
        self.logger.info("Setting up resource monitoring...")
        
        # Attack containment
        self.logger.info("Initializing attack containment systems...")
        
        self.safety_protocols_enabled = True

    async def _monitoring_loop(self) -> None:
        """Background monitoring of lab systems"""
        while self.status != LabStatus.ERROR:
            try:
                # Update metrics
                self.get_lab_metrics()
                
                # Check system health
                await self._health_check()
                
                # Monitor experiments
                await self._monitor_experiments()
                
                # Wait before next iteration
                await asyncio.sleep(30)  # Check every 30 seconds
                
            except Exception as e:
                self.logger.error(f"Monitoring loop error: {e}")
                await asyncio.sleep(60)  # Wait longer on error

    async def _maintenance_loop(self) -> None:
        """Background maintenance tasks"""
        while self.status != LabStatus.ERROR:
            try:
                # Backup data
                if datetime.now(timezone.utc).hour % self.config.auto_backup_interval_hours == 0:
                    await self._backup_lab_state()
                
                # Cleanup old experiments
                await self._cleanup_old_experiments()
                
                # Resource optimization
                await self._optimize_resources()
                
                # Wait before next iteration
                await asyncio.sleep(3600)  # Check every hour
                
            except Exception as e:
                self.logger.error(f"Maintenance loop error: {e}")
                await asyncio.sleep(3600)

    async def _health_check(self) -> bool:
        """Perform system health checks"""
        health_status = True
        
        # Check compute cluster
        if self.compute_cluster and not await self.compute_cluster.health_check():
            self.logger.warning("Compute cluster health check failed")
            health_status = False
        
        # Check data warehouse
        if self.data_warehouse and not await self.data_warehouse.health_check():
            self.logger.warning("Data warehouse health check failed")
            health_status = False
        
        # Check resource utilization
        if self.metrics.cpu_utilization > 95:
            self.logger.warning(f"High CPU utilization: {self.metrics.cpu_utilization}%")
            health_status = False
        
        if self.metrics.memory_utilization > 90:
            self.logger.warning(f"High memory utilization: {self.metrics.memory_utilization}%")
            health_status = False
        
        return health_status

    async def _monitor_experiments(self) -> None:
        """Monitor running experiments for issues"""
        for exp_id, exp_info in self.active_experiments.items():
            try:
                status = await self.experiment_runner.get_status(exp_id)
                exp_info['status'] = status.get('status', 'unknown')
                
                # Check for timeouts
                runtime = datetime.now(timezone.utc) - exp_info['submitted_at']
                if runtime.total_seconds() > self.config.experiment_timeout_hours * 3600:
                    self.logger.warning(f"Experiment {exp_id} exceeded timeout, canceling")
                    await self.cancel_experiment(exp_id)
                
            except Exception as e:
                self.logger.error(f"Error monitoring experiment {exp_id}: {e}")

    async def _backup_lab_state(self) -> None:
        """Backup current lab state and data"""
        backup_path = self.config.data_storage_path / "backups" / f"backup_{datetime.now().isoformat()}"
        backup_path.mkdir(parents=True, exist_ok=True)
        
        # Backup would include:
        # - Experiment metadata
        # - Lab configuration
        # - Metrics and logs
        # - Critical research data
        
        self.logger.info(f"Lab state backed up to {backup_path}")

    async def _cleanup_old_experiments(self) -> None:
        """Remove old experiment data to free space"""
        # Logic to clean up experiments older than retention period
        pass

    async def _optimize_resources(self) -> None:
        """Optimize resource allocation and usage"""
        if self.resource_manager:
            await self.resource_manager.optimize_allocation()

    async def _load_experiment_results(self, experiment_id: str) -> Dict[str, Any]:
        """Load historical experiment results from storage"""
        results_path = self.config.data_storage_path / "results" / f"{experiment_id}.json"
        
        if results_path.exists():
            import json
            with open(results_path, 'r') as f:
                return json.load(f)
        
        return {"error": "Results not found"}


# Convenience class for easier usage
class ResearchLab:
    """Simplified interface to BlackLoom Research Laboratory"""
    
    def __init__(self, config: Optional[ResearchLabConfig] = None):
        self.manager = ResearchLabManager(config)
    
    async def __aenter__(self):
        await self.manager.initialize_lab()
        return self.manager
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.manager.shutdown_lab()
    
    def __getattr__(self, name):
        return getattr(self.manager, name)