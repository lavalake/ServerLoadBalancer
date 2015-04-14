# ServerLoadBalancer
Web services often use multiple web and application servers for scalability. 
Many cloud computing platforms like AWS allow the number of servers to be 
scaled up or down based on the load experienced by the servers.
In such load balanced systems, clients typically connect to a server that
acts as the load balancer and routes their requests to one of the servers. 
A dedicated load balancer using consistent hashing is a popular solution today,
but it suffers from being an expensive additional piece of hardware and has limited customizability.
The goal in this problem is to develop a load-balancing solution that uses the OpenFlow API
and a POX controller to perform load balancing using generic OpenFlow enabled switches 
and thereby reduce costs of a server acting as the load balancer.
