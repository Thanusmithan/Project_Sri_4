import React, { createContext, useContext, useState, useEffect } from "react";

const ServicesContext = createContext();

export const useServices = () => useContext(ServicesContext);

export const ServicesProvider = ({ children }) => {
    const [services, setServices] = useState([]);

    useEffect(() => {
        fetchServices();
    }, []);

    const fetchServices = async () => {
        try {
            const response = await fetch("http://localhost:5000/api/services");
            const data = await response.json();
            setServices(data);
        } catch (error) {
            console.error("Failed to fetch services:", error);
        }
    };

    const addService = async (service) => {
        try {
            const response = await fetch("http://localhost:5000/api/services", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(service),
            });
            if (response.ok) fetchServices();
        } catch (error) {
            console.error("Failed to add service:", error);
        }
    };

    const editService = async (id, updatedService) => {
        try {
            await fetch(`http://localhost:5000/api/services/${id}`, {
                method: "PUT",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(updatedService),
            });
            fetchServices();
        } catch (error) {
            console.error("Failed to edit service:", error);
        }
    };

    const deleteService = async (id) => {
        try {
            await fetch(`http://localhost:5000/api/services/${id}`, { method: "DELETE" });
            fetchServices();
        } catch (error) {
            console.error("Failed to delete service:", error);
        }
    };

    return (
        <ServicesContext.Provider value={{ services, addService, editService, deleteService }}>
            {children}
        </ServicesContext.Provider>
    );
};
