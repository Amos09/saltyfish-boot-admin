#### ***ApplicationService 最核心的类，负责业务流程的编排，但本身不负责任何业务逻辑***
```sql
ApplicationService应用服务：最核心的类，负责业务流程的编排，但本身不负责任何业务逻辑
DTO Assembler：负责将内部领域模型转化为可对外的DTO
Command、Query、Event对象：作为ApplicationService的入参
返回的DTO：作为ApplicationService的出参
```