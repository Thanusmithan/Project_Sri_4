import React, { useState } from 'react';
import './Css/Stock.css';
import Header from './Componets/Admin_Header';
import Footer from './Componets/Footer';
import { Button, Table, Badge, Card, Row, Col, Form, Dropdown, Modal } from 'react-bootstrap';
import { FaPlus, FaFileExport, FaUser, FaEdit, FaTrashAlt,FaTimes,FaEllipsisV,FaSave } from 'react-icons/fa';
import { saveAs } from 'file-saver';

const StockManagement = () => {
  const [products, setProducts] = useState([
    { id: 1, name: 'Ashwagandha', category: 'Herbs', sku: 'AY001', incoming: 20, price: 15, stock: 50, value: 750, status: 'In Stock' },
    { id: 2, name: 'Triphala', category: 'Digestive Health', sku: 'AY002', incoming: 15, price: 10, stock: 10, value: 100, status: 'Low Stock' },
  ]);

  const [editingProductId, setEditingProductId] = useState(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [showModal, setShowModal] = useState(false);
  const [newProduct, setNewProduct] = useState({
    name: '',
    category: '',
    sku: '',
    incoming: 0,
    price: 0,
    stock: 0,
    value: 0,
  });

  const [editedProduct, setEditedProduct] = useState({
    name: '',
    category: '',
    sku: '',
    incoming: 0,
    price: 0,
    stock: 0,
    value: 0,
    status: ''
  });

  const filteredProducts = products.filter(product =>
    product.name.toLowerCase().includes(searchTerm.toLowerCase())
  );

  const handleSearchChange = (e) => {
    setSearchTerm(e.target.value);
  };

  const exportToCSV = () => {
    const csvRows = [
      ['Product Name', 'Category', 'SKU', 'Incoming Now', 'Unit Price', 'In Stock', 'Total Value', 'Status'],
      ...filteredProducts.map(product => [
        product.name,
        product.category,
        product.sku,
        product.incoming,
        `LKR ${product.price}`,
        product.stock,
        `LKR ${product.value}`,
        product.status,
      ])
    ];

    const csvContent = csvRows.map(row => row.join(',')).join('\n');
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    saveAs(blob, 'stock_data.csv');
  };

  const handleEditToggle = (productId) => {
    const productToEdit = products.find(product => product.id === productId);
    setEditingProductId(productId);
    setEditedProduct({ ...productToEdit });
  };

  const handleSave = () => {
    setProducts(prevProducts =>
      prevProducts.map(product =>
        product.id === editedProduct.id ? { ...editedProduct, value: editedProduct.price * editedProduct.stock, status: getStockStatus(editedProduct.stock) } : product
      )
    );
    setEditingProductId(null);
  };

  const getStockStatus = (stock) => {
    return stock <= 10 ? 'Low Stock' : 'In Stock';
  };

  const handleDelete = (productId) => {
    setProducts(prevProducts => prevProducts.filter(product => product.id !== productId));
  };

  const handleModalClose = () => setShowModal(false);
  const handleModalShow = () => setShowModal(true);

  const handleNewProductChange = (e) => {
    const { name, value } = e.target;
    setNewProduct(prevProduct => ({ ...prevProduct, [name]: value }));
  };

  const handleAddProduct = () => {
    if (!newProduct.name || !newProduct.category || !newProduct.sku || newProduct.incoming <= 0 || newProduct.price <= 0 || newProduct.stock <= 0) {
      alert("Please fill all fields correctly!");
      return;
    }
    const newProductData = {
      id: Date.now(),
      ...newProduct,
      value: newProduct.price * newProduct.stock,
      status: getStockStatus(newProduct.stock),
    };
    setProducts(prevProducts => [...prevProducts, newProductData]);
    setShowModal(false);
    setNewProduct({
      name: '',
      category: '',
      sku: '',
      incoming: 0,
      price: 0,
      stock: 0,
      value: 0,
    });
  };

  const getStatusClass = (status) => {
    return status === 'Low Stock' ? 'bg-danger text-white' : 'bg-success text-white';
  };

  return (
    <>
      <Header />
      <div className="stock-management">
        <div className="stock-management-container">
          <h2 className="stock-header text-center mb-3">Stock Management</h2>
          <Row className="summary-cards">
            <Col md={4}>
              <Card className="summary-card text-center">
                <Card.Body>
                  <Card.Title style={{ color: 'black' }}>Categories</Card.Title>
                  <Card.Text>Total Items</Card.Text>
                  <h3>{[...new Set(products.map(product => product.category))].length}</h3>
                </Card.Body>
              </Card>
            </Col>
            <Col md={4}>
              <Card className="summary-card text-center ">
                <Card.Body>
                  <Card.Title style={{ color: 'black' }}>Total Products</Card.Title>
                  <Card.Text>Current Stock</Card.Text>
                  <h3>{products.length}</h3>
                </Card.Body>
              </Card>
            </Col>
            <Col md={4}>
              <Card className="summary-card text-center">
                <Card.Body>
                  <Card.Title style={{ color: 'red' }}>Low Stock</Card.Title>
                  <Card.Text>Reorder Needed</Card.Text>
                  <h3>{products.filter(product => product.stock <= 10).length}</h3>
                </Card.Body>
              </Card>
            </Col>
          </Row>
          <hr />

          <div className="table-actions">
            <h4 className="stock-header">Stock Details</h4>
            <Row className="action-row d-flex justify-content-between align-items-center">
              {/* Search Column */}
              <Col md={6} className="search-col">
                <Form.Control
                  type="text"
                  placeholder="Search Products..."
                  className="search-input"
                  value={searchTerm}
                  onChange={handleSearchChange}
                  style={{ width: '500px' }}
                />
              </Col>

              {/* Action Buttons Column */}
              <Col md={6} className="action-buttons-right d-flex justify-content-end">
                <Button variant="success" className="action-button large-button  me-2" onClick={handleModalShow}>
                  <FaPlus /> Add Product
                </Button>
                <Button variant="outline-secondary" className="action-button large-button  me-2">
                  <FaUser /> Supplier
                </Button>
                <Button variant="outline-secondary" className="action-button large-button" onClick={exportToCSV}>
                  <FaFileExport /> Export
                </Button>
              </Col>
            </Row>

          </div>

          <div className="table-container">
            <Table bordered hover responsive>
              <thead>
                <tr>
                  <th>Product Name</th>
                  <th>Category</th>
                  <th>SKU</th>
                  <th>Incoming Now</th>
                  <th>Unit Price</th>
                  <th>In Stock</th>
                  <th>Total Value</th>
                  <th>Status</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody>
                {filteredProducts.map((product, index) => (
                  <tr key={index}>
                    <td>
                      {editingProductId === product.id ? (
                        <Form.Control
                          type="text"
                          name="name"
                          value={editedProduct.name}
                          onChange={(e) => setEditedProduct({ ...editedProduct, name: e.target.value })}
                        />
                      ) : (
                        product.name
                      )}
                    </td>
                    <td>
                      {editingProductId === product.id ? (
                        <Form.Control
                          type="text"
                          name="category"
                          value={editedProduct.category}
                          onChange={(e) => setEditedProduct({ ...editedProduct, category: e.target.value })}
                        />
                      ) : (
                        product.category
                      )}
                    </td>
                    <td>{product.sku}</td>
                    <td>{editingProductId === product.id ? (
                      <Form.Control
                        type="number"
                        name="incoming"
                        value={editedProduct.incoming}
                        onChange={(e) => setEditedProduct({ ...editedProduct, incoming: parseInt(e.target.value) })}
                      />
                    ) : (
                      product.incoming
                    )}
                    </td>
                    <td>{editingProductId === product.id ? (
                      <Form.Control
                        type="number"
                        name="price"
                        value={editedProduct.price}
                        onChange={(e) => setEditedProduct({ ...editedProduct, price: parseFloat(e.target.value) })}
                      />
                    ) : (
                      `LKR ${product.price}`
                    )}
                    </td>
                    <td>{editingProductId === product.id ? (
                      <Form.Control
                        type="number"
                        name="stock"
                        value={editedProduct.stock}
                        onChange={(e) => setEditedProduct({ ...editedProduct, stock: parseInt(e.target.value) })}
                      />
                    ) : (
                      product.stock
                    )}
                    </td>
                    <td>{`LKR ${product.value}`}</td>
                    <td>
                      <Badge className={getStatusClass(product.status)}>{product.status}</Badge>
                    </td>
                    {/* <td>
                      {editingProductId === product.id ? (
                        <Dropdown drop='start'>
                          <Dropdown.Toggle variant="outline-primary" id={`dropdown-${product.id}`}></Dropdown.Toggle>
                          <Dropdown.Menu>
                            <Dropdown.Item onClick={handleSave}>Save</Dropdown.Item>
                            <Dropdown.Item onClick={() => setEditingProductId(null)}>Cancel</Dropdown.Item>
                          </Dropdown.Menu>
                        </Dropdown>
                      ) : (
                        <Dropdown drop='start'>
                          <Dropdown.Toggle variant="outline-primary" id={`dropdown-${product.id}`}></Dropdown.Toggle>
                          <Dropdown.Menu>
                            <Dropdown.Item onClick={() => handleEditToggle(product.id)}>Edit</Dropdown.Item>
                            <Dropdown.Item onClick={() => handleDelete(product.id)}>Delete</Dropdown.Item>
                          </Dropdown.Menu>
                        </Dropdown>
                      )}
                    </td> */}
                    <td>
                      {editingProductId === product.id ? (
                        <Dropdown drop='start'>
                          <Dropdown.Toggle variant="outline-primary" id={`dropdown-${product.id}`}>
                            <FaEllipsisV />
                          </Dropdown.Toggle>
                          <Dropdown.Menu>
                            <Dropdown.Item as="button" onClick={handleSave}>
                              <FaSave className="me-2" /> Save
                            </Dropdown.Item>
                            <Dropdown.Item as="button" onClick={() => setEditingProductId(null)}>
                              <FaTimes className="me-2" /> Cancel
                            </Dropdown.Item>
                          </Dropdown.Menu>
                        </Dropdown>
                      ) : (
                        <Dropdown drop='start'>
                          <Dropdown.Toggle variant="outline-primary" id={`dropdown-${product.id}`}>
                            <FaEllipsisV />
                          </Dropdown.Toggle>
                          <Dropdown.Menu>
                            <Dropdown.Item as="button" onClick={() => handleEditToggle(product.id)}>
                              <FaEdit className="me-2" /> Edit
                            </Dropdown.Item>
                            <Dropdown.Item as="button" onClick={() => handleDelete(product.id)}>
                              <FaTrashAlt className="me-2" /> Delete
                            </Dropdown.Item>
                          </Dropdown.Menu>
                        </Dropdown>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </Table>
          </div>
        </div>
        <Modal show={showModal} onHide={handleModalClose}>
          <Modal.Header closeButton>
            <Modal.Title>Add New Product</Modal.Title>
          </Modal.Header>
          <Modal.Body>
            <Form>
              {/* Text Fields */}
              {['name', 'category', 'sku'].map((field) => (
                <Form.Group key={field} className="mb-3">
                  <Form.Label>{field.charAt(0).toUpperCase() + field.slice(1)}</Form.Label>
                  <Form.Control
                    type="text"
                    name={field}
                    placeholder={`Enter ${field === 'sku' ? 'SKU Code (e.g., AY001)' : field}`}
                    value={newProduct[field]}
                    onChange={handleNewProductChange}
                    required
                  />
                  <Form.Text className="text-muted">
                    {field === 'name' && 'Provide a clear product name (e.g., Ashwagandha).'}
                    {field === 'category' && 'Specify the product category (e.g., Digestive Health).'}
                    {field === 'sku' && 'Enter a unique SKU identifier for tracking purposes.'}
                  </Form.Text>
                </Form.Group>
              ))}

              {/* Numeric Fields */}
              {['incoming', 'price', 'stock'].map((field) => (
                <Form.Group key={field} className="mb-3">
                  <Form.Label>{field.charAt(0).toUpperCase() + field.slice(1)}</Form.Label>
                  <Form.Control
                    type="number"
                    name={field}
                    placeholder={`Enter ${field === 'incoming' ? 'Incoming Quantity' : field}`}
                    value={newProduct[field]}
                    onChange={handleNewProductChange}
                    required
                    min="1"
                  />
                  <Form.Text className="text-muted">
                    {field === 'incoming' && 'Number of units being added to the stock.'}
                    {field === 'price' && 'Specify the unit price (e.g., LKR 15).'}
                    {field === 'stock' && 'Enter the current stock quantity available.'}
                  </Form.Text>
                </Form.Group>
              ))}
            </Form>
          </Modal.Body>
          <Modal.Footer>
            <Button variant="secondary" onClick={handleModalClose}>Close</Button>
            <Button variant="primary" onClick={handleAddProduct}>Save Changes</Button>
          </Modal.Footer>
        </Modal>

      </div>
      <Footer />
    </>
  );
};

export default StockManagement;
