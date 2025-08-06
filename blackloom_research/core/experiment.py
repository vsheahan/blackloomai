"""
BlackLoom Research Experiment Framework
Defines experiment structure and execution framework for AI security research
"""

import asyncio
import json
import logging
import uuid
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Any, Type, Union
from dataclasses import dataclass, field, asdict
from enum import Enum

import numpy as np
from concurrent.futures import ThreadPoolExecutor


class ExperimentStatus(Enum):
    """Experiment execution status"""
    CREATED = "created"
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ExperimentType(Enum):
    """Types of research experiments"""
    VULNERABILITY_DISCOVERY = "vulnerability_discovery"
    ATTACK_GENERATION = "attack_generation"
    DEFENSE_EVALUATION = "defense_evaluation"
    THREAT_INTELLIGENCE = "threat_intelligence"
    MULTIMODAL_SECURITY = "multimodal_security"
    HUMAN_AI_INTERACTION = "human_ai_interaction"
    BEHAVIORAL_ANALYSIS = "behavioral_analysis"
    PERFORMANCE_BENCHMARKING = "performance_benchmarking"


@dataclass
class ExperimentMetadata:
    """Metadata for research experiments"""
    name: str
    description: str
    experiment_type: ExperimentType
    researcher: str
    institution: str
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    tags: List[str] = field(default_factory=list)
    estimated_runtime_hours: float = 1.0
    resource_requirements: Dict[str, Any] = field(default_factory=dict)
    ethics_approval: bool = False
    dual_use_research: bool = False
    generates_attacks: bool = False
    uses_personal_data: bool = False
    safety_measures: List[str] = field(default_factory=list)


@dataclass
class ExperimentConfig:
    """Configuration parameters for experiments"""
    batch_size: int = 32
    learning_rate: float = 0.001
    max_iterations: int = 1000
    random_seed: int = 42
    output_dir: str = "./experiment_output"
    checkpoint_interval: int = 100
    enable_logging: bool = True
    log_level: str = "INFO"
    custom_params: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ExperimentResult:
    """Results from completed experiment"""
    experiment_id: str
    status: ExperimentStatus
    start_time: datetime
    end_time: Optional[datetime] = None
    duration_seconds: float = 0.0
    success: bool = False
    error_message: Optional[str] = None
    metrics: Dict[str, float] = field(default_factory=dict)
    artifacts: List[str] = field(default_factory=list)  # Paths to output files
    discoveries: List[Dict[str, Any]] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert result to dictionary for serialization"""
        result_dict = asdict(self)
        # Convert datetime objects to ISO strings
        if self.start_time:
            result_dict['start_time'] = self.start_time.isoformat()
        if self.end_time:
            result_dict['end_time'] = self.end_time.isoformat()
        result_dict['status'] = self.status.value
        return result_dict


class Experiment(ABC):
    """
    Abstract base class for all research experiments
    Provides common functionality and enforces experiment structure
    """
    
    def __init__(self, metadata: ExperimentMetadata, config: Optional[ExperimentConfig] = None):
        self.id = str(uuid.uuid4())
        self.metadata = metadata
        self.config = config or ExperimentConfig()
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        
        # Execution state
        self.status = ExperimentStatus.CREATED
        self.start_time: Optional[datetime] = None
        self.end_time: Optional[datetime] = None
        self.result: Optional[ExperimentResult] = None
        
        # Runtime data
        self.metrics: Dict[str, float] = {}
        self.artifacts: List[str] = []
        self.discoveries: List[Dict[str, Any]] = []
        
        # Setup output directory
        self.output_dir = Path(self.config.output_dir) / self.id
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Setup logging
        if self.config.enable_logging:
            self._setup_logging()

    @abstractmethod
    async def setup(self) -> bool:
        """
        Setup experiment environment and resources
        
        Returns:
            bool: True if setup successful, False otherwise
        """
        pass

    @abstractmethod
    async def execute(self) -> Dict[str, Any]:
        """
        Execute the main experiment logic
        
        Returns:
            Dict[str, Any]: Experiment-specific results
        """
        pass

    @abstractmethod
    async def cleanup(self) -> None:
        """Clean up experiment resources and temporary files"""
        pass

    async def validate_preconditions(self) -> bool:
        """
        Validate experiment preconditions and safety requirements
        
        Returns:
            bool: True if all preconditions are met
        """
        # Check ethics approval for sensitive research
        if self.metadata.dual_use_research and not self.metadata.ethics_approval:
            self.logger.error("Dual-use research requires ethics approval")
            return False
        
        # Verify safety measures for attack generation
        if self.metadata.generates_attacks:
            if not self.metadata.safety_measures:
                self.logger.error("Attack generation requires safety measures")
                return False
        
        # Check data privacy compliance
        if self.metadata.uses_personal_data:
            if 'privacy_compliance' not in self.metadata.tags:
                self.logger.error("Personal data usage requires privacy compliance")
                return False
        
        return True

    async def run(self) -> ExperimentResult:
        """
        Execute the complete experiment workflow
        
        Returns:
            ExperimentResult: Comprehensive experiment results
        """
        self.start_time = datetime.now(timezone.utc)
        self.status = ExperimentStatus.RUNNING
        
        try:
            # Validate preconditions
            if not await self.validate_preconditions():
                raise RuntimeError("Experiment preconditions not met")
            
            # Setup phase
            self.logger.info(f"Setting up experiment: {self.metadata.name}")
            if not await self.setup():
                raise RuntimeError("Experiment setup failed")
            
            # Execution phase
            self.logger.info(f"Executing experiment: {self.id}")
            execution_results = await self.execute()
            
            # Process results
            await self._process_results(execution_results)
            
            # Mark as completed
            self.status = ExperimentStatus.COMPLETED
            self.end_time = datetime.now(timezone.utc)
            
            self.logger.info(f"Experiment completed successfully: {self.id}")
            
        except asyncio.CancelledError:
            self.status = ExperimentStatus.CANCELLED
            self.logger.info(f"Experiment cancelled: {self.id}")
            
        except Exception as e:
            self.status = ExperimentStatus.FAILED
            self.end_time = datetime.now(timezone.utc)
            self.logger.error(f"Experiment failed: {self.id}, Error: {e}")
            
        finally:
            # Always cleanup
            try:
                await self.cleanup()
            except Exception as e:
                self.logger.error(f"Cleanup failed: {e}")
        
        # Generate final result
        self.result = self._generate_result()
        
        # Save result to disk
        await self._save_result()
        
        return self.result

    def add_metric(self, name: str, value: float) -> None:
        """Add a metric to the experiment results"""
        self.metrics[name] = value
        self.logger.info(f"Metric recorded: {name} = {value}")

    def add_artifact(self, file_path: str) -> None:
        """Add an output artifact to the experiment results"""
        self.artifacts.append(file_path)
        self.logger.info(f"Artifact recorded: {file_path}")

    def add_discovery(self, discovery: Dict[str, Any]) -> None:
        """Add a research discovery to the experiment results"""
        discovery['timestamp'] = datetime.now(timezone.utc).isoformat()
        discovery['experiment_id'] = self.id
        self.discoveries.append(discovery)
        self.logger.info(f"Discovery recorded: {discovery.get('type', 'unknown')}")

    async def checkpoint(self, checkpoint_data: Dict[str, Any]) -> None:
        """Save experiment checkpoint for resumability"""
        checkpoint_path = self.output_dir / f"checkpoint_{datetime.now().isoformat()}.json"
        
        checkpoint_info = {
            'experiment_id': self.id,
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'status': self.status.value,
            'metrics': self.metrics,
            'data': checkpoint_data
        }
        
        with open(checkpoint_path, 'w') as f:
            json.dump(checkpoint_info, f, indent=2, default=str)
        
        self.logger.info(f"Checkpoint saved: {checkpoint_path}")

    def _setup_logging(self) -> None:
        """Setup experiment-specific logging"""
        log_file = self.output_dir / "experiment.log"
        
        # Create file handler
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(getattr(logging, self.config.log_level))
        
        # Create formatter
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        file_handler.setFormatter(formatter)
        
        # Add handler to logger
        self.logger.addHandler(file_handler)
        self.logger.setLevel(getattr(logging, self.config.log_level))

    async def _process_results(self, execution_results: Dict[str, Any]) -> None:
        """Process and validate experiment results"""
        # Add execution results to metrics
        if isinstance(execution_results, dict):
            for key, value in execution_results.items():
                if isinstance(value, (int, float)):
                    self.add_metric(key, float(value))

    def _generate_result(self) -> ExperimentResult:
        """Generate comprehensive experiment result"""
        duration = 0.0
        if self.start_time and self.end_time:
            duration = (self.end_time - self.start_time).total_seconds()
        elif self.start_time:
            duration = (datetime.now(timezone.utc) - self.start_time).total_seconds()
        
        return ExperimentResult(
            experiment_id=self.id,
            status=self.status,
            start_time=self.start_time or datetime.now(timezone.utc),
            end_time=self.end_time,
            duration_seconds=duration,
            success=(self.status == ExperimentStatus.COMPLETED),
            metrics=self.metrics.copy(),
            artifacts=self.artifacts.copy(),
            discoveries=self.discoveries.copy(),
            metadata={
                'experiment_name': self.metadata.name,
                'experiment_type': self.metadata.experiment_type.value,
                'researcher': self.metadata.researcher,
                'tags': self.metadata.tags
            }
        )

    async def _save_result(self) -> None:
        """Save experiment result to disk"""
        if self.result:
            result_file = self.output_dir / "result.json"
            with open(result_file, 'w') as f:
                json.dump(self.result.to_dict(), f, indent=2, default=str)


class ExperimentRunner:
    """
    Manages execution of multiple experiments with resource allocation
    """
    
    def __init__(self, 
                 compute_cluster=None,
                 data_warehouse=None,
                 max_concurrent: int = 4,
                 timeout_hours: int = 24):
        self.compute_cluster = compute_cluster
        self.data_warehouse = data_warehouse
        self.max_concurrent = max_concurrent
        self.timeout_hours = timeout_hours
        self.logger = logging.getLogger(__name__)
        
        # Experiment tracking
        self.running_experiments: Dict[str, asyncio.Task] = {}
        self.queued_experiments: List[tuple] = []  # (experiment, isolation_id)
        self.completed_experiments: Dict[str, ExperimentResult] = {}
        
        # Resource management
        self.executor = ThreadPoolExecutor(max_workers=max_concurrent)
        
        # Start background processor
        self._processor_task = asyncio.create_task(self._process_queue())

    async def submit_experiment(self, experiment: Experiment, isolation_id: str) -> str:
        """
        Submit experiment for execution
        
        Args:
            experiment: The experiment to run
            isolation_id: Security isolation identifier
            
        Returns:
            str: Experiment ID
        """
        self.queued_experiments.append((experiment, isolation_id))
        self.logger.info(f"Experiment queued: {experiment.id}")
        return experiment.id

    async def get_status(self, experiment_id: str) -> Dict[str, Any]:
        """Get experiment status and progress"""
        if experiment_id in self.running_experiments:
            return {
                'status': 'running',
                'experiment_id': experiment_id,
                'queue_position': None
            }
        
        # Check if queued
        for i, (exp, _) in enumerate(self.queued_experiments):
            if exp.id == experiment_id:
                return {
                    'status': 'queued',
                    'experiment_id': experiment_id,
                    'queue_position': i + 1
                }
        
        # Check if completed
        if experiment_id in self.completed_experiments:
            result = self.completed_experiments[experiment_id]
            return {
                'status': result.status.value,
                'experiment_id': experiment_id,
                'result': result.to_dict()
            }
        
        return {
            'status': 'not_found',
            'experiment_id': experiment_id
        }

    async def cancel_experiment(self, experiment_id: str) -> bool:
        """Cancel a running or queued experiment"""
        # Cancel if running
        if experiment_id in self.running_experiments:
            task = self.running_experiments[experiment_id]
            task.cancel()
            
            try:
                await task
            except asyncio.CancelledError:
                pass
            
            del self.running_experiments[experiment_id]
            return True
        
        # Remove if queued
        for i, (exp, isolation_id) in enumerate(self.queued_experiments):
            if exp.id == experiment_id:
                del self.queued_experiments[i]
                return True
        
        return False

    async def _process_queue(self) -> None:
        """Background task to process experiment queue"""
        while True:
            try:
                # Start new experiments if resources available
                while (len(self.running_experiments) < self.max_concurrent 
                       and self.queued_experiments):
                    
                    experiment, isolation_id = self.queued_experiments.pop(0)
                    
                    # Start experiment execution
                    task = asyncio.create_task(
                        self._run_experiment_with_isolation(experiment, isolation_id)
                    )
                    
                    self.running_experiments[experiment.id] = task
                    self.logger.info(f"Started experiment: {experiment.id}")
                
                # Check for completed experiments
                completed_ids = []
                for exp_id, task in self.running_experiments.items():
                    if task.done():
                        completed_ids.append(exp_id)
                        
                        try:
                            result = await task
                            self.completed_experiments[exp_id] = result
                            self.logger.info(f"Experiment completed: {exp_id}")
                        except Exception as e:
                            self.logger.error(f"Experiment failed: {exp_id}, Error: {e}")
                
                # Clean up completed experiments
                for exp_id in completed_ids:
                    del self.running_experiments[exp_id]
                
                # Wait before next iteration
                await asyncio.sleep(1)
                
            except Exception as e:
                self.logger.error(f"Queue processor error: {e}")
                await asyncio.sleep(5)

    async def _run_experiment_with_isolation(self, 
                                           experiment: Experiment, 
                                           isolation_id: str) -> ExperimentResult:
        """Run experiment with security isolation"""
        try:
            # Apply resource limits and isolation
            # This would integrate with containerization in production
            
            # Execute experiment
            result = await asyncio.wait_for(
                experiment.run(),
                timeout=self.timeout_hours * 3600
            )
            
            return result
            
        except asyncio.TimeoutError:
            self.logger.error(f"Experiment timeout: {experiment.id}")
            experiment.status = ExperimentStatus.FAILED
            return experiment._generate_result()
            
        except Exception as e:
            self.logger.error(f"Experiment execution error: {experiment.id}, Error: {e}")
            experiment.status = ExperimentStatus.FAILED
            return experiment._generate_result()

    async def shutdown(self) -> None:
        """Shutdown experiment runner"""
        # Cancel processor
        if hasattr(self, '_processor_task'):
            self._processor_task.cancel()
        
        # Cancel all running experiments
        for task in self.running_experiments.values():
            task.cancel()
        
        # Wait for completion
        if self.running_experiments:
            await asyncio.gather(*self.running_experiments.values(), return_exceptions=True)
        
        # Shutdown executor
        self.executor.shutdown(wait=True)