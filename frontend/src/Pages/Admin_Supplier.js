// AdminSupplier.js
import React, { useState } from "react";
import "./Css/Supplier.css";
import Header from "./Componets/Admin_Header";
import Footer from "./Componets/Footer";
import {
  Button,
  Table,
  Card,
  Row,
  Col,
  Form,
  Dropdown,
  Modal,
  Alert,
} from "react-bootstrap";
import { FaPlus, FaFileExport,FaEllipsisV,FaTrashAlt,FaEdit } from "react-icons/fa";
import { saveAs } from "file-saver";

const AdminSupplier = () => {
  const [suppliers, setSuppliers] = useState([
    {
      name: "Herbal Life",
      contact: "0771234567",
      email: "contact@herbalife.com",
      address: "Colombo",
      productName: "Herbal Tea",
      category: "Tea",
      status: "active",
    },
    {
      name: "Ayurvedic Supply Co",
      contact: "0769876543",
      email: "info@ayurvedic.com",
      address: "Kandy",
      productName: "Ayurvedic Powder",
      category: "Powder",
      status: "inactive",
    },
  ]);

  const [showAddModal, setShowAddModal] = useState(false);
  const [editingSupplierIndex, setEditingSupplierIndex] = useState(null);
  const [supplierDetails, setSupplierDetails] = useState({
    name: "",
    contact: "",
    email: "",
    address: "",
    productName: "",
    category: "",
    status: "active",
  });
  const [searchTerm, setSearchTerm] = useState("");
  const [showAlert, setShowAlert] = useState(false);
  const [showSuccessAlert, setShowSuccessAlert] = useState(false);

  const handleSearchChange = (e) => setSearchTerm(e.target.value);
  const filteredSuppliers = suppliers.filter((supplier) =>
    supplier.name.toLowerCase().includes(searchTerm.toLowerCase())
  );

  const exportToCSV = () => {
    const csvContent = [
      [
        "Supplier Name",
        "Contact",
        "Email",
        "Address",
        "Product Name",
        "Category",
        "Status",
      ],
      ...filteredSuppliers.map((supplier) => [
        supplier.name,
        supplier.contact,
        supplier.email,
        supplier.address,
        supplier.productName,
        supplier.category,
        supplier.status,
      ]),
    ]
      .map((row) => row.join(","))
      .join("\n");
    const blob = new Blob([csvContent], { type: "text/csv;charset=utf-8;" });
    saveAs(blob, "suppliers_data.csv");
  };

  const handleAddOrUpdateSupplier = () => {
    if (Object.values(supplierDetails).some((field) => !field)) {
      setShowAlert(true);
      setTimeout(() => setShowAlert(false), 2000);
      return;
    }

    const updatedSuppliers =
      editingSupplierIndex !== null
        ? suppliers.map((sup, i) =>
          i === editingSupplierIndex ? supplierDetails : sup
        )
        : [...suppliers, supplierDetails];

    setSuppliers(updatedSuppliers);
    setShowSuccessAlert(true);
    setTimeout(() => setShowSuccessAlert(false), 2000);
    resetModal();
  };

  const resetModal = () => {
    setSupplierDetails({
      name: "",
      contact: "",
      email: "",
      address: "",
      productName: "",
      category: "",
      status: "active",
    });
    setEditingSupplierIndex(null);
    setShowAddModal(false);
    setShowAlert(false);
    setShowSuccessAlert(false);
  };

  const handleEditSupplier = (index) => {
    setEditingSupplierIndex(index);
    setSupplierDetails(suppliers[index]);
    setShowAddModal(true);
  };

  const handleDeleteSupplier = (index) => {
    const updatedSuppliers = suppliers.filter((sup, i) => i !== index);
    setSuppliers(updatedSuppliers);
  };

  const handleStatusChange = (index, newStatus) => {
    const updatedSuppliers = suppliers.map((sup, i) =>
      i === index ? { ...sup, status: newStatus } : sup
    );
    setSuppliers(updatedSuppliers);
  };

  return (
    <>
      <Header />
      <div className="supplier-management">
        <div
          className="supplier-management-container mx-auto"
          style={{ width: "90%" }}
        >
          <h2 className="supplier-header text-center mb-5">
            Supplier Management
          </h2>
          <Row className="summary-cards">
            <Col md={6}>
              <Card className="summary-card text-center">
                <Card.Body>
                  <Card.Title>Total Suppliers</Card.Title>
                  <h3>{suppliers.length}</h3>
                </Card.Body>
              </Card>
            </Col>
            <Col md={6}>
              <Card className="summary-card text-center">
                <Card.Body>
                  <Card.Title>Active Suppliers</Card.Title>
                  <h3 >
                    {suppliers.filter((s) => s.status === "active").length}
                  </h3>
                </Card.Body>
              </Card>
            </Col>
          </Row>
          <hr />
          <div className="table-actions">
            <Row className="action-row d-flex justify-content-between align-items-center">
              {/* Search Column */}
              <Col md={6} className="search-col">
                <Form.Control
                  type="text"
                  placeholder="Search Suppliers..."
                  className="search-input"
                  value={searchTerm}
                  onChange={handleSearchChange}
                  style={{ width: '500px' }}
                />
              </Col>

              {/* Action Buttons Column */}
              <Col md={6} className="action-buttons-right d-flex justify-content-end">
                <Button
                  variant="success"
                  className="action-button me-2"
                  onClick={() => setShowAddModal(true)}
                >
                  <FaPlus /> Add Supplier
                </Button>
                <Button
                  variant="outline-secondary"
                  className="action-button"
                  onClick={exportToCSV}
                >
                  <FaFileExport /> Export
                </Button>
              </Col>
            </Row>

          </div>
          <div className="table-container">
            <Table bordered hover responsive className="supplier-table ">
              <thead>
                <tr>
                  <th >Supplier Name</th>
                  <th>Contact</th>
                  <th>Email</th>
                  <th>Address</th>
                  <th>Product Name</th>
                  <th>Category</th>
                  <th>Status</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody>
                {filteredSuppliers.map((supplier, index) => (
                  <tr
                    key={index}
                    className={
                      supplier.status === "active"
                        ? "active-row"
                        : "inactive-row"
                    }
                  >
                    <td>{supplier.name}</td>
                    <td>{supplier.contact}</td>
                    <td>{supplier.email}</td>
                    <td>{supplier.address}</td>
                    <td>{supplier.productName}</td>
                    <td>{supplier.category}</td>
                    <td>{supplier.status}</td>
                    <td>
                      <Dropdown drop="start">
                        <Dropdown.Toggle
                          className="supplier-dropdown-toggle-custom"
                          variant="secondary"
                          id={`dropdownMenuButton-${supplier.id}`}
                        >
                          <FaEllipsisV />
                        </Dropdown.Toggle>
                        <Dropdown.Menu className="dropdown-menu-custom">
                          <Dropdown.Item
                            as="button"
                            onClick={() => handleEditSupplier(index)}
                            className="dropdown-item-custom"
                          >
                            <FaEdit className="me-2" /> Edit
                          </Dropdown.Item>
                          <Dropdown.Item
                            as="button"
                            onClick={() => handleDeleteSupplier(index)}
                            className="dropdown-item-custom"
                          >
                            <FaTrashAlt className="me-2" /> Delete
                          </Dropdown.Item>
                          <Dropdown.Item
                            as="button"
                            onClick={() =>
                              handleStatusChange(
                                index,
                                supplier.status === "active" ? "inactive" : "active"
                              )
                            }
                            className="dropdown-item-custom"
                          >
                            <i
                              className={
                                supplier.status === "active"
                                  ? "fas fa-pause-circle me-2"
                                  : "fas fa-check-circle me-2"
                              }
                            ></i>
                            {supplier.status === "active"
                              ? "Mark as Inactive"
                              : "Mark as Active"}
                          </Dropdown.Item>
                        </Dropdown.Menu>
                      </Dropdown>
                    </td>

                  </tr>
                ))}
              </tbody>
            </Table>
          </div>
        </div>
        <Modal show={showAddModal} onHide={resetModal}>
          <Modal.Header closeButton>
            <Modal.Title>
              {editingSupplierIndex !== null
                ? "Edit Supplier"
                : "Add New Supplier"}
            </Modal.Title>
          </Modal.Header>
          <Modal.Body>
            {showAlert && (
              <Alert variant="danger">Please fill in all fields!</Alert>
            )}
            {showSuccessAlert && (
              <Alert variant="success">Supplier updated successfully!</Alert>
            )}
            <Form>
              <Form.Group controlId="formSupplierName">
                <Form.Label>Supplier Name</Form.Label>
                <Form.Control
                  type="text"
                  placeholder="Enter supplier name"
                  value={supplierDetails.name}
                  onChange={(e) =>
                    setSupplierDetails({
                      ...supplierDetails,
                      name: e.target.value,
                    })
                  }
                />
              </Form.Group>

              <Form.Group controlId="formSupplierContact">
                <Form.Label>Contact</Form.Label>
                <Form.Control
                  type="text"
                  placeholder="Enter contact number"
                  value={supplierDetails.contact}
                  onChange={(e) =>
                    setSupplierDetails({
                      ...supplierDetails,
                      contact: e.target.value,
                    })
                  }
                />
              </Form.Group>

              <Form.Group controlId="formSupplierEmail">
                <Form.Label>Email</Form.Label>
                <Form.Control
                  type="email"
                  placeholder="Enter email"
                  value={supplierDetails.email}
                  onChange={(e) =>
                    setSupplierDetails({
                      ...supplierDetails,
                      email: e.target.value,
                    })
                  }
                />
              </Form.Group>

              <Form.Group controlId="formSupplierAddress">
                <Form.Label>Address</Form.Label>
                <Form.Control
                  type="text"
                  placeholder="Enter address"
                  value={supplierDetails.address}
                  onChange={(e) =>
                    setSupplierDetails({
                      ...supplierDetails,
                      address: e.target.value,
                    })
                  }
                />
              </Form.Group>

              <Form.Group controlId="formProductName">
                <Form.Label>Product Name</Form.Label>
                <Form.Control
                  type="text"
                  placeholder="Enter product name"
                  value={supplierDetails.productName}
                  onChange={(e) =>
                    setSupplierDetails({
                      ...supplierDetails,
                      productName: e.target.value,
                    })
                  }
                />
              </Form.Group>

              <Form.Group controlId="formCategory">
                <Form.Label>Category</Form.Label>
                <Form.Control
                  type="text"
                  placeholder="Enter category"
                  value={supplierDetails.category}
                  onChange={(e) =>
                    setSupplierDetails({
                      ...supplierDetails,
                      category: e.target.value,
                    })
                  }
                />
              </Form.Group>

              <Form.Group controlId="formStatus">
                <Form.Label>Status</Form.Label>
                <Dropdown
                  onSelect={(status) =>
                    setSupplierDetails({ ...supplierDetails, status })
                  }
                >
                  <Dropdown.Toggle variant="success" id="dropdown-status" className="dropdown-status">
                    {supplierDetails.status}
                  </Dropdown.Toggle>
                  <Dropdown.Menu>
                    <Dropdown.Item eventKey="active">Active</Dropdown.Item>
                    <Dropdown.Item eventKey="inactive">Inactive</Dropdown.Item>
                  </Dropdown.Menu>
                </Dropdown>
              </Form.Group>
            </Form>
          </Modal.Body>
          <Modal.Footer>
            <Button variant="secondary" onClick={resetModal}>
              Close
            </Button>
            <Button variant="primary" onClick={handleAddOrUpdateSupplier}>
              {editingSupplierIndex !== null
                ? "Update Supplier"
                : "Add Supplier"}
            </Button>
          </Modal.Footer>
        </Modal>
      </div>
      <Footer />
    </>
  );
};

export default AdminSupplier;
